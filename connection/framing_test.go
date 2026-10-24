package connection

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func yamuxHeader(msgType uint8, length uint32) []byte {
	h := make([]byte, yamuxHeaderSize)
	h[1] = msgType
	binary.BigEndian.PutUint32(h[4:8], 3)
	binary.BigEndian.PutUint32(h[8:12], length)
	return h
}

func TestFrameWriterKeepsYamuxFramesWhole(t *testing.T) {
	rec := &recordingConn{}
	w := &frameWriter{Conn: rec}
	write := func(p []byte) {
		t.Helper()
		if n, err := w.Write(p); err != nil || n != len(p) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	data := yamuxHeader(yamuxTypeData, 5)
	write(data)
	if len(rec.writes) != 0 {
		t.Fatal("data header reached the transport before its body")
	}
	write([]byte("hello"))
	windowUpdate := yamuxHeader(1, 65536) // length is a window delta, no body
	write(windowUpdate)
	fin := yamuxHeader(yamuxTypeData, 0) // flags only, no body
	write(fin)
	write(data)
	write([]byte("world"))
	want := [][]byte{append(append([]byte(nil), data...), "hello"...), windowUpdate, fin, append(append([]byte(nil), data...), "world"...)}
	if len(rec.writes) != len(want) {
		t.Fatalf("got %d transport writes, want %d", len(rec.writes), len(want))
	}
	for i := range want {
		if !bytes.Equal(rec.writes[i], want[i]) {
			t.Fatalf("write %d = %x, want %x", i, rec.writes[i], want[i])
		}
	}
}

func TestWriteFrameIsOneWrite(t *testing.T) {
	rec := &recordingConn{}
	if err := writeFrame(rec, controlMessage{Type: "renew_ack", FlowID: "f", Sequence: 1}, 16<<10); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("metadata frame took %d writes", len(rec.writes))
	}
	var msg controlMessage
	if err := readFrame(bytes.NewReader(rec.writes[0]), &msg, 16<<10); err != nil || msg.Type != "renew_ack" {
		t.Fatalf("round trip: %+v %v", msg, err)
	}
}
