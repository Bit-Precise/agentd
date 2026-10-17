package policygate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Capture a real ClientHello emitted by the standard TLS implementation. Reads
// immediately reach EOF because generating the first flight needs no server.
type captureConn struct{ bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func realHello(t *testing.T, name string, maxVersion uint16) []byte {
	t.Helper()
	capture := new(captureConn)
	client := tls.Client(capture, &tls.Config{ServerName: name, InsecureSkipVerify: true, MaxVersion: maxVersion}) // No server exists; only capture the first flight.
	if err := client.Handshake(); err == nil {
		t.Fatal("handshake unexpectedly completed without a server")
	}
	if capture.Len() < 5 {
		t.Fatal("TLS client did not emit a ClientHello")
	}
	return bytes.Clone(capture.Bytes())
}

func handshakeBytes(t *testing.T, records []byte) []byte {
	t.Helper()
	var handshake []byte
	for len(records) > 0 {
		if len(records) < 5 {
			t.Fatal("invalid generated TLS record")
		}
		length := int(binary.BigEndian.Uint16(records[3:5]))
		if records[0] != 22 || len(records) < 5+length {
			t.Fatal("unexpected generated TLS message")
		}
		handshake = append(handshake, records[5:5+length]...)
		records = records[5+length:]
	}
	return handshake
}

func recordsFor(handshake []byte, chunk int) []byte {
	var records []byte
	for len(handshake) != 0 {
		length := min(len(handshake), chunk)
		records = append(records, 22, 3, 1, byte(length>>8), byte(length))
		records = append(records, handshake[:length]...)
		handshake = handshake[length:]
	}
	return records
}

func inspectBytes(t *testing.T, raw []byte, expected string, tcpChunk int) ([]byte, error) {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	written := make(chan struct{})
	go func() {
		defer close(written)
		defer a.Close()
		for len(raw) > 0 {
			length := min(len(raw), tcpChunk)
			if _, err := a.Write(raw[:length]); err != nil {
				return
			}
			raw = raw[length:]
		}
	}()
	got, err := Inspect(ctx, b, expected)
	_ = b.Close()
	<-written
	return got, err
}

func TestInspectRealTLSClientHelloPreservesBytes(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		raw := realHello(t, "oa.example", version)
		for _, chunk := range []int{1, 7, len(raw)} {
			got, err := inspectBytes(t, raw, "OA.EXAMPLE.", chunk)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("TLS %x, TCP chunk %d: exact replay lost: %v", version, chunk, err)
			}
		}
	}
}

func TestInspectClientHelloAcrossTLSRecords(t *testing.T) {
	handshake := handshakeBytes(t, realHello(t, "oa.example", tls.VersionTLS13))
	for _, chunk := range []int{1, 2, 17, 257} {
		raw := recordsFor(handshake, chunk)
		got, err := inspectBytes(t, raw, "oa.example", 11)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("TLS record chunk %d: %v", chunk, err)
		}
	}
}

func extensionOffset(t *testing.T, hello []byte) int {
	t.Helper()
	position := 4 + 2 + 32
	position += 1 + int(hello[position])
	position += 2 + int(binary.BigEndian.Uint16(hello[position:position+2]))
	position += 1 + int(hello[position])
	if position+2 > len(hello) {
		t.Fatal("generated ClientHello lacks extensions")
	}
	return position
}

func addExtension(t *testing.T, hello, extension []byte) []byte {
	t.Helper()
	result := bytes.Clone(hello)
	offset := extensionOffset(t, result)
	length := int(binary.BigEndian.Uint16(result[offset : offset+2]))
	result = append(result, extension...)
	binary.BigEndian.PutUint16(result[offset:offset+2], uint16(length+len(extension)))
	length = len(result) - 4
	result[1], result[2], result[3] = byte(length>>16), byte(length>>8), byte(length)
	return result
}

func TestInspectRejectsMissingMismatchedOrEncryptedSNI(t *testing.T) {
	plain := realHello(t, "oa.example", tls.VersionTLS13)
	noName := realHello(t, "", tls.VersionTLS13)
	hello := handshakeBytes(t, plain)
	ech := recordsFor(addExtension(t, hello, []byte{0xfe, 0x0d, 0, 0}), maxRecordBytes)
	for _, tc := range []struct {
		name     string
		data     []byte
		expected string
		want     error
	}{
		{"different domain", plain, "other.example", ErrMismatch},
		{"suffix is insufficient", plain, "example", ErrMismatch},
		{"missing SNI", noName, "oa.example", ErrNoSNI},
		{"ECH extension", ech, "oa.example", ErrECH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspectBytes(t, tc.data, tc.expected, 37)
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("Inspect = %x, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestInspectRejectsMalformedLengthsAndDuplicates(t *testing.T) {
	hello := handshakeBytes(t, realHello(t, "oa.example", tls.VersionTLS12))
	offset := extensionOffset(t, hello)
	badExtensions := bytes.Clone(hello)
	binary.BigEndian.PutUint16(badExtensions[offset:offset+2], binary.BigEndian.Uint16(badExtensions[offset:offset+2])+1)
	oversizedHandshake := bytes.Clone(hello)
	oversizedHandshake[1], oversizedHandshake[2], oversizedHandshake[3] = 255, 255, 255
	wrongHandshake := bytes.Clone(hello)
	wrongHandshake[0] = 2
	var sniExtension []byte
	for pos := offset + 2; pos+4 <= len(hello); {
		length := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		if binary.BigEndian.Uint16(hello[pos:pos+2]) == 0 {
			sniExtension = hello[pos : pos+4+length]
			break
		}
		pos += 4 + length
	}
	if sniExtension == nil {
		t.Fatal("generated SNI extension not found")
	}
	tooManyBytes := make([]byte, MaxClientHelloBytes-2)
	tooManyBytes[0] = 1
	length := len(tooManyBytes) - 4
	tooManyBytes[1], tooManyBytes[2], tooManyBytes[3] = byte(length>>16), byte(length>>8), byte(length)
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"extension length", recordsFor(badExtensions, maxRecordBytes), ErrMalformed},
		{"handshake length", recordsFor(oversizedHandshake, maxRecordBytes), ErrLimit},
		{"wrong handshake type", recordsFor(wrongHandshake, maxRecordBytes), ErrMalformed},
		{"duplicate SNI", recordsFor(addExtension(t, hello, sniExtension), maxRecordBytes), ErrMalformed},
		{"record type", []byte{23, 3, 3, 0, 1, 0}, ErrMalformed},
		{"empty record", []byte{22, 3, 3, 0, 0}, ErrMalformed},
		{"record length", []byte{22, 3, 3, 0xff, 0xff}, ErrMalformed},
		{"total read limit", recordsFor(tooManyBytes, maxRecordBytes), ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspectBytes(t, tc.raw, "oa.example", 4096)
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("malformed input accepted or wrong error: %v", err)
			}
		})
	}
	for _, raw := range [][]byte{{22}, {22, 3, 3, 0, 10, 1}, recordsFor(hello[:12], maxRecordBytes)} {
		if got, err := inspectBytes(t, raw, "oa.example", 1); err == nil || got != nil {
			t.Fatal("truncated ClientHello accepted")
		}
	}
}

func TestInspectCanceledOrSlowClient(t *testing.T) {
	for _, cancelExplicitly := range []bool{false, true} {
		a, b := net.Pipe()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		if cancelExplicitly {
			cancel()
		}
		start := time.Now()
		_, err := Inspect(ctx, b, "oa.example")
		cancel()
		_ = a.Close()
		_ = b.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("slow/canceled inspection did not stop promptly: %v", err)
		}
	}
}

func TestInspectDoesNotConsumeFollowingRecord(t *testing.T) {
	raw := realHello(t, "oa.example", tls.VersionTLS13)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { _, _ = a.Write(append(bytes.Clone(raw), []byte("following-record")...)) }()
	got, err := Inspect(ctx, b, "oa.example")
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatalf("initial ClientHello: %v", err)
	}
	cancel() // successful inspection must detach its cancellation callback
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	rest := make([]byte, len("following-record"))
	if _, err := io.ReadFull(b, rest); err != nil || string(rest) != "following-record" {
		t.Fatalf("post-ClientHello bytes lost: %q, %v", rest, err)
	}
}
