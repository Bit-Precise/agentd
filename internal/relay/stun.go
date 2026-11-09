package relay

import (
	"encoding/binary"
	"net"
)

// serveSTUN answers RFC 5389 Binding requests with XOR-MAPPED-ADDRESS, the
// reflexive address P2P would use (protocol 2.6, reserved).
func serveSTUN(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := stunResponse(buf[:n], addr); resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

const stunMagic = 0x2112A442

func stunResponse(req []byte, addr net.Addr) []byte {
	if len(req) < 20 || binary.BigEndian.Uint16(req[0:2]) != 0x0001 || binary.BigEndian.Uint32(req[4:8]) != stunMagic {
		return nil
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}
	ip4 := ua.IP.To4()
	var attr []byte
	port := uint16(ua.Port) ^ uint16(stunMagic>>16)
	if ip4 != nil {
		attr = make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], 0x0020)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		attr[5] = 0x01
		binary.BigEndian.PutUint16(attr[6:8], port)
		binary.BigEndian.PutUint32(attr[8:12], binary.BigEndian.Uint32(ip4)^stunMagic)
	} else {
		ip := ua.IP.To16()
		attr = make([]byte, 24)
		binary.BigEndian.PutUint16(attr[0:2], 0x0020)
		binary.BigEndian.PutUint16(attr[2:4], 20)
		attr[5] = 0x02
		binary.BigEndian.PutUint16(attr[6:8], port)
		key := append(binary.BigEndian.AppendUint32(nil, stunMagic), req[8:20]...)
		for i := 0; i < 16; i++ {
			attr[8+i] = ip[i] ^ key[i]
		}
	}
	resp := make([]byte, 20, 20+len(attr))
	binary.BigEndian.PutUint16(resp[0:2], 0x0101)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
	copy(resp[4:20], req[4:20])
	return append(resp, attr...)
}
