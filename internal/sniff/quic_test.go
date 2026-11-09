package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

func TestQUICKeysMatchRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp := quicClientKeys(quicV1, dcid)
	if hex.EncodeToString(key) != "1f369613dd76d5467730efcbe3b1a22d" || hex.EncodeToString(iv) != "fa044b2f42a3fd3b46fb255c" || hex.EncodeToString(hp) != "9f50449e04a0e810283a1e9933adedd2" {
		t.Fatalf("v1 keys: %x %x %x", key, iv, hp)
	}
	key, iv, hp = quicClientKeys(quicV2, dcid)
	// RFC 9369 Appendix A.1.
	if hex.EncodeToString(key) != "8b1a0bc121284290a29e0971b5cd045d" || hex.EncodeToString(iv) != "91f73e2351d8fa91660e909f" || hex.EncodeToString(hp) != "45b95e15235d6f45a6b19cbcb0294ba9" {
		t.Fatalf("v2 keys: %x %x %x", key, iv, hp)
	}
}

// clientHello captures the handshake message crypto/tls sends.
func quicClientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}).Handshake()
	hdr := make([]byte, 5)
	io.ReadFull(b, hdr)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	io.ReadFull(b, body)
	a.Close()
	b.Close()
	return body
}

func cryptoFrame(off int, data []byte) []byte {
	f := []byte{0x06}
	f = binary.BigEndian.AppendUint32(f, 0x80000000|uint32(off))
	f = binary.BigEndian.AppendUint32(f, 0x80000000|uint32(len(data)))
	return append(f, data...)
}

// protect builds a client Initial packet (RFC 9001 5) around frames.
func protect(version uint32, dcid []byte, pn uint32, frames []byte) []byte {
	key, iv, hpKey := quicClientKeys(version, dcid)
	for len(frames) < 1100 {
		frames = append(frames, 0) // PADDING
	}
	first := byte(0xc3)
	if version == quicV2 {
		first = 0xd3
	}
	hdr := []byte{first}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // scid, token length
	length := 4 + len(frames) + 16
	hdr = binary.BigEndian.AppendUint16(hdr, 0x4000|uint16(length))
	pnOffset := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	pkt := append(append([]byte(nil), hdr...), gcm.Seal(nil, nonce, frames, hdr)...)
	hp, _ := aes.NewCipher(hpKey)
	mask := make([]byte, 16)
	hp.Encrypt(mask, pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func TestQUICSnifferReassemblesClientHello(t *testing.T) {
	ch := quicClientHello(t, "course.ucas.edu.cn")
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, v := range []uint32{quicV1, quicV2} {
		half := len(ch) / 2
		p1 := protect(v, dcid, 0, cryptoFrame(0, ch[:half]))
		p2 := protect(v, dcid, 1, append([]byte{0x01}, cryptoFrame(half, ch[half:])...))
		var s QUICSniffer
		if sni, done := s.Add(p1); done {
			t.Fatalf("v%x: done after half a ClientHello (%q)", v, sni)
		}
		if sni, done := s.Add(p2); !done || sni != "course.ucas.edu.cn" {
			t.Fatalf("v%x: sni %q done %v", v, sni, done)
		}
		// Out of order works too.
		var r QUICSniffer
		r.Add(p2)
		if sni, done := r.Add(p1); !done || sni != "course.ucas.edu.cn" {
			t.Fatalf("v%x reordered: %q %v", v, sni, done)
		}
	}
	var s QUICSniffer
	if _, done := s.Add([]byte("hello, not quic")); !done {
		t.Fatal("non-QUIC datagrams must end sniffing")
	}
}
