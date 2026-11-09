package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
)

// QUIC Initial packets are protected with keys derived from the destination
// connection ID alone (RFC 9001 5.2), so the ClientHello inside them can be
// read without any state. This is how TUN mode learns the SNI of QUIC flows
// to real addresses (design 5.2).

var (
	quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicV2Salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

var errNotQUIC = errors.New("not a QUIC Initial packet")

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		panic(err)
	}
	return out
}

// quicClientKeys derives the client Initial key, IV and header-protection key.
func quicClientKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt, prefix := quicV1Salt, "quic "
	if version == quicV2 {
		salt, prefix = quicV2Salt, "quicv2 "
	}
	initial := hkdf.Extract(sha256.New, dcid, salt)
	client := hkdfExpandLabel(initial, "client in", 32)
	return hkdfExpandLabel(client, prefix+"key", 16), hkdfExpandLabel(client, prefix+"iv", 12), hkdfExpandLabel(client, prefix+"hp", 16)
}

func readVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

// QUICInitialCrypto decrypts one client Initial packet and returns the
// CRYPTO frame data it carries, keyed by stream offset.
func QUICInitialCrypto(pkt []byte) (map[uint64][]byte, error) {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil, errNotQUIC
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	ptype := (pkt[0] >> 4) & 0x03
	switch {
	case version == quicV1 && ptype == 0, version == quicV2 && ptype == 1:
	default:
		return nil, errNotQUIC
	}
	p := 5
	dcidLen := int(pkt[p])
	p++
	if dcidLen > 20 || len(pkt) < p+dcidLen+1 {
		return nil, errNotQUIC
	}
	dcid := pkt[p : p+dcidLen]
	p += dcidLen
	scidLen := int(pkt[p])
	p += 1 + scidLen
	tokLen, n, ok := readVarint(pkt[p:])
	if !ok {
		return nil, errNotQUIC
	}
	p += n + int(tokLen)
	length, n, ok := readVarint(pkt[p:])
	if !ok || p+n+int(length) > len(pkt) || length < 20 {
		return nil, errNotQUIC
	}
	p += n
	pnOffset := p
	key, iv, hpKey := quicClientKeys(version, dcid)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	if pnOffset+4+16 > len(pkt) {
		return nil, errNotQUIC
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[pnOffset+4:pnOffset+4+16])
	hdr := append([]byte(nil), pkt[:pnOffset+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}
	hdr = hdr[:pnOffset+pnLen]
	payloadEnd := pnOffset + int(length)
	ciphertext := pkt[pnOffset+pnLen : payloadEnd]
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	aesKey, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesKey)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return nil, errNotQUIC
	}
	out := map[uint64][]byte{}
	for q := 0; q < len(plain); {
		ft, n, ok := readVarint(plain[q:])
		if !ok {
			break
		}
		q += n
		switch {
		case ft == 0x00 || ft == 0x01: // PADDING, PING
		case ft == 0x02 || ft == 0x03: // ACK: largest, delay, range count, first range, ranges
			var vals [4]uint64
			for i := range vals {
				v, n, ok := readVarint(plain[q:])
				if !ok {
					return out, nil
				}
				vals[i], q = v, q+n
			}
			for i := uint64(0); i < vals[2]*2; i++ {
				_, n, ok := readVarint(plain[q:])
				if !ok {
					return out, nil
				}
				q += n
			}
			if ft == 0x03 {
				for i := 0; i < 3; i++ {
					_, n, ok := readVarint(plain[q:])
					if !ok {
						return out, nil
					}
					q += n
				}
			}
		case ft == 0x06: // CRYPTO
			off, n, ok := readVarint(plain[q:])
			if !ok {
				return out, nil
			}
			q += n
			l, n, ok := readVarint(plain[q:])
			if !ok || q+n+int(l) > len(plain) {
				return out, nil
			}
			q += n
			out[off] = plain[q : q+int(l)]
			q += int(l)
		case ft == 0x1c: // CONNECTION_CLOSE
			return out, nil
		default:
			return out, nil
		}
	}
	return out, nil
}

// QUICSniffer accumulates client Initial packets of one flow until the
// ClientHello is complete (Chrome's post-quantum ClientHello spans several).
type QUICSniffer struct {
	crypto map[uint64][]byte
}

// Add feeds one datagram. done is true once the SNI is known or the flow is
// clearly not QUIC; sni is empty when there is none.
func (s *QUICSniffer) Add(pkt []byte) (sni string, done bool) {
	frames, err := QUICInitialCrypto(pkt)
	if err != nil {
		return "", true
	}
	if s.crypto == nil {
		s.crypto = map[uint64][]byte{}
	}
	for k, v := range frames {
		s.crypto[k] = v
	}
	offs := make([]uint64, 0, len(s.crypto))
	for k := range s.crypto {
		offs = append(offs, k)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var hs []byte
	for _, o := range offs {
		if o != uint64(len(hs)) {
			if o > uint64(len(hs)) {
				break
			}
			d := s.crypto[o]
			if o+uint64(len(d)) <= uint64(len(hs)) {
				continue
			}
			hs = append(hs, d[uint64(len(hs))-o:]...)
			continue
		}
		hs = append(hs, s.crypto[o]...)
	}
	if len(hs) < 4 {
		return "", false
	}
	// Wrap the handshake bytes as TLS records for the ClientHello parser.
	var rec []byte
	for rest := hs; len(rest) > 0; {
		n := len(rest)
		if n > 1<<14 {
			n = 1 << 14
		}
		rec = append(rec, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		rec = append(rec, rest[:n]...)
		rest = rest[n:]
	}
	sni, complete, err := ParseClientHello(rec)
	if err != nil {
		return "", true
	}
	return sni, complete
}
