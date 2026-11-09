package elevator

import (
	"bufio"
	"bytes"
	"testing"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("{\"ok\":true}\n") // the handshake line comes first
	writeFrame(&b, framePacket, []byte{0x45, 0, 0, 20})
	writeFrame(&b, frameJSON, []byte(`{"event":"network"}`))
	writeFrame(&b, framePacket, make([]byte, 65535))
	r := bufio.NewReader(&b)
	if line, _ := r.ReadBytes('\n'); string(line) != "{\"ok\":true}\n" {
		t.Fatalf("handshake line %q", line)
	}
	for i, want := range []struct {
		typ byte
		n   int
	}{{framePacket, 4}, {frameJSON, 19}, {framePacket, 65535}} {
		typ, p, err := readFrame(r)
		if err != nil || typ != want.typ || len(p) != want.n {
			t.Fatalf("frame %d: %v %c %d", i, err, typ, len(p))
		}
	}
	if err := writeFrame(&b, framePacket, make([]byte, 70000)); err == nil {
		t.Fatal("oversized frames must be refused")
	}
}
