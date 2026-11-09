package sniff

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// clientHello captures the bytes a real TLS client sends first.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(time.Second))
		c.Handshake()
		a.Close()
	}()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64<<10)
	n, _ := io.ReadAtLeast(b, buf, 5)
	b.Close()
	return buf[:n]
}

func TestParseClientHello(t *testing.T) {
	hello := clientHello(t, "course.ucas.edu.cn")
	sni, complete, err := ParseClientHello(hello)
	if err != nil || !complete || sni != "course.ucas.edu.cn" {
		t.Fatalf("ParseClientHello = %q %v %v", sni, complete, err)
	}
	_, complete, err = ParseClientHello(hello[:20])
	if err != nil || complete {
		t.Fatalf("partial hello: complete=%v err=%v", complete, err)
	}
	if _, _, err := ParseClientHello([]byte("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("non-TLS data accepted")
	}
}

// slowReader delivers data in small pieces, like a ClientHello split across TCP segments.
type slowReader struct {
	data  []byte
	chunk int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := s.chunk
	if n > len(s.data) {
		n = len(s.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, s.data[:n])
	s.data = s.data[n:]
	return n, nil
}

func TestSniffAccumulatesSegments(t *testing.T) {
	hello := clientHello(t, "nas.home.example.com")
	r := Sniff(&slowReader{data: append([]byte(nil), hello...), chunk: 100}, 16<<10)
	if r.Kind != TLS || r.SNI != "nas.home.example.com" {
		t.Fatalf("Sniff = %+v", r)
	}
	if !bytes.Equal(r.Data, hello) {
		t.Fatal("sniffed bytes must be returned for replay")
	}
}

func TestSniffSSHAndUnknown(t *testing.T) {
	r := Sniff(bytes.NewReader([]byte("SSH-2.0-OpenSSH_9.6\r\n")), 16<<10)
	if r.Kind != SSH {
		t.Fatalf("ssh: %+v", r)
	}
	r = Sniff(bytes.NewReader([]byte("\x00\x01binary")), 16<<10)
	if r.Kind != Unknown || len(r.Data) == 0 {
		t.Fatalf("unknown: %+v", r)
	}
}

func TestSSHFirstLine(t *testing.T) {
	if !IsSSH([]byte("SSH-")) || IsSSH([]byte("GET ")) {
		t.Fatal("IsSSH")
	}
}
