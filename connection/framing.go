package connection

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("write metadata length: %w", err)
	}
	return writeAll(w, data)
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
