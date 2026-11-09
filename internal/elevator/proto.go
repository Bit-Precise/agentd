//go:build linux || darwin

// Package elevator is the privileged helper for TUN mode (design 5.2): it
// creates the TUN device, takes over the default route and the system DNS,
// and passes the device to the unprivileged agentd over a unix socket. When
// agentd goes away it restores routes and DNS. One instance per device may
// hold the TUN at a time.
package elevator

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
)

// conn frames newline-delimited JSON on a unix stream with optional
// descriptors.
type conn struct {
	c   *net.UnixConn
	buf []byte
	fds []int
}

func (c *conn) send(v any, f *os.File) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	var oob []byte
	if f != nil {
		oob = syscall.UnixRights(int(f.Fd()))
	}
	_, _, err = c.c.WriteMsgUnix(b, oob, nil)
	return err
}

// recv reads one message; a descriptor that arrived with it is returned.
func (c *conn) recv(v any) (*os.File, error) {
	for {
		if i := bytes.IndexByte(c.buf, '\n'); i >= 0 {
			line := c.buf[:i]
			c.buf = c.buf[i+1:]
			var f *os.File
			if len(c.fds) > 0 {
				f = os.NewFile(uintptr(c.fds[0]), "tun")
				c.fds = c.fds[1:]
			}
			return f, json.Unmarshal(line, v)
		}
		b := make([]byte, 8192)
		oob := make([]byte, syscall.CmsgSpace(4*4))
		n, oobn, _, _, err := c.c.ReadMsgUnix(b, oob)
		if oobn > 0 {
			msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
			if perr == nil {
				for _, m := range msgs {
					if fds, err := syscall.ParseUnixRights(&m); err == nil {
						c.fds = append(c.fds, fds...)
					}
				}
			}
		}
		if n > 0 {
			c.buf = append(c.buf, b[:n]...)
			continue
		}
		if err == nil {
			err = errors.New("connection closed")
		}
		return nil, err
	}
}
