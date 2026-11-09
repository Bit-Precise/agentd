//go:build linux || darwin

package tun

import (
	"os"
	"runtime"
	"syscall"
)

// FileDevice is a TUN device opened by the elevator and passed to the
// unprivileged daemon as a file descriptor. Linux devices carry bare IP
// packets (IFF_NO_PI, no virtio header); macOS utun prefixes each packet
// with a 4-byte address family.
type FileDevice struct {
	f   *os.File
	mtu int
	hdr int
}

// NewFileDevice wraps a TUN descriptor.
func NewFileDevice(f *os.File, mtu int) *FileDevice {
	d := &FileDevice{f: f, mtu: mtu}
	if runtime.GOOS == "darwin" {
		d.hdr = 4
	}
	return d
}

func (d *FileDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	buf := bufs[0][offset-d.hdr:]
	n, err := d.f.Read(buf)
	if n <= d.hdr {
		return 0, err
	}
	sizes[0] = n - d.hdr
	return 1, nil
}

func (d *FileDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		b = b[offset-d.hdr:]
		if d.hdr == 4 {
			b[0], b[1], b[2] = 0, 0, 0
			if b[4]>>4 == 6 {
				b[3] = syscall.AF_INET6
			} else {
				b[3] = syscall.AF_INET
			}
		}
		if _, err := d.f.Write(b); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *FileDevice) BatchSize() int    { return 1 }
func (d *FileDevice) MTU() (int, error) { return d.mtu, nil }
func (d *FileDevice) Close() error      { return d.f.Close() }
