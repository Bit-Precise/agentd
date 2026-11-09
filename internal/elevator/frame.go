package elevator

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// On Windows a wintun session cannot be handed to another process, so the
// elevator relays packets over the agentd connection after the JSON
// handshake: each frame is [type][u16 length][payload].
const (
	framePacket byte = 'P'
	frameJSON   byte = 'J'
)

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 0xffff {
		return errors.New("frame too large")
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	p := make([]byte, binary.BigEndian.Uint16(hdr[1:3]))
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}
