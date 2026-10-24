package connection

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// Length is checked before allocation. Metadata never uses a streaming JSON
// decoder over the connection, which could consume the first business bytes.
func readFrame(r io.Reader, value any, limit int) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("read metadata length: %w", err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || uint64(n) > uint64(limit) {
		return ErrMetadataLimit
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrProtocol // Never reflect credentials or peer-controlled JSON.
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func writeFrame(w io.Writer, value any, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	if len(data) == 0 || len(data) > limit {
		return ErrMetadataLimit
	}
	// One Write per frame: packet transports send each Write as its own packet,
	// so a separate length prefix would cost an extra request.
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	if err := writeAll(w, frame); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

// yamux frame header layout (hashicorp/yamux const.go): version, type, flags,
// stream ID and a length that, for data frames, is the body length.
const (
	yamuxHeaderSize = 12
	yamuxTypeData   = 0
)

// frameWriter hands yamux frames to the transport whole. yamux's send loop
// writes a data frame's 12-byte header and then its body as two Writes; over
// packet-up each Write becomes a POST, and the body would then wait for the
// transport's minimum POST interval. The header is held only when the body is
// certain to follow: a data frame with a nonzero length. Window updates, pings,
// go-aways and empty data frames carry no body and pass straight through. yamux
// writes from a single goroutine, so no locking is needed.
type frameWriter struct {
	net.Conn
	header []byte
}

func (w *frameWriter) Write(p []byte) (int, error) {
	if w.header != nil {
		frame := append(w.header, p...)
		w.header = nil
		if err := writeAll(w.Conn, frame); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(p) == yamuxHeaderSize && p[1] == yamuxTypeData && binary.BigEndian.Uint32(p[8:12]) > 0 {
		w.header = append(make([]byte, 0, yamuxHeaderSize+int(binary.BigEndian.Uint32(p[8:12]))), p...)
		return len(p), nil
	}
	return w.Conn.Write(p)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
