package session

import (
	"io"
	"net"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
)

// Mux is a yamux session over an encrypted Conn (protocol 3.4).
type Mux = yamux.Session

// Stream is one multiplexed stream.
type Stream = yamux.Stream

// KeepAliveInterval and WriteTimeout are the yamux keepalive and connection
// write timeout (protocol 3.4); variables so tests can shorten them.
var (
	KeepAliveInterval = 30 * time.Second
	WriteTimeout      = 30 * time.Second
)

// MuxConfig returns the yamux parameters from protocol 3.4.
func MuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = 256
	c.EnableKeepAlive = true
	c.KeepAliveInterval = KeepAliveInterval
	c.ConnectionWriteTimeout = WriteTimeout
	c.MaxIncomingStreams = 1024
	c.InitialStreamWindowSize = 256 << 10
	c.MaxStreamWindowSize = 16 << 20
	c.MaxMessageSize = 64 << 10
	c.LogOutput = io.Discard
	return c
}

// NewMux starts yamux on conn. The side that dialled the connection is the
// client and uses odd stream IDs.
func NewMux(conn net.Conn, client bool) (*Mux, error) {
	if client {
		return yamux.Client(conn, MuxConfig(), nil)
	}
	return yamux.Server(conn, MuxConfig(), nil)
}
