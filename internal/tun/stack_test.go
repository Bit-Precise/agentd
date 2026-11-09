package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// pipeDev is a Device whose packets come from and go to a client stack.
type pipeDev struct {
	in     chan []byte // packets from the "OS" into the TUN
	client *channel.Endpoint
	once   sync.Once
	done   chan struct{}
}

func (p *pipeDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case b := <-p.in:
		sizes[0] = copy(bufs[0][offset:], b)
		return 1, nil
	case <-p.done:
		return 0, net.ErrClosed
	}
}

func (p *pipeDev) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		data := append([]byte(nil), b[offset:]...)
		proto := header.IPv4ProtocolNumber
		if data[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		p.client.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (p *pipeDev) BatchSize() int    { return 1 }
func (p *pipeDev) MTU() (int, error) { return 1500, nil }
func (p *pipeDev) Close() error      { p.once.Do(func() { close(p.done) }); return nil }

// clientStack is the "operating system": it owns 198.18.0.1 and routes
// everything into the TUN.
func clientStack(t *testing.T, dev *pipeDev) *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, 1500, "")
	dev.client = ep
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(GatewayAddr4.As4()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	go func() {
		for {
			pkt := ep.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			b := append([]byte(nil), v.AsSlice()...)
			v.Release()
			pkt.DecRef()
			select {
			case dev.in <- b:
			case <-dev.done:
				return
			}
		}
	}()
	t.Cleanup(func() { ep.Close(); s.Close() })
	return s
}

func TestStackRecoversTCPAndUDP(t *testing.T) {
	dev := &pipeDev{in: make(chan []byte, 256), done: make(chan struct{})}
	cs := clientStack(t, dev)
	type seen struct{ dst netip.AddrPort }
	tcpSeen := make(chan seen, 1)
	st, err := NewStack(dev, Handlers{
		TCP: func(c net.Conn, src, dst netip.AddrPort) {
			tcpSeen <- seen{dst}
			defer c.Close()
			io.Copy(c, c)
		},
		UDP: func(c *gonet.UDPConn, src, dst netip.AddrPort) bool {
			buf := make([]byte, 1500)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				return false
			}
			c.Write(append([]byte("reply to "+dst.String()+": "), buf[:n]...))
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	fake := netip.MustParseAddr("198.18.7.9")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(fake.As4()), Port: 443}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through the tun: %v", err)
	}
	payload := make([]byte, 256<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	go c.Write(payload)
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo: %v", err)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatal("echo mismatch")
		}
	}
	c.Close()
	if s := <-tcpSeen; s.dst != netip.AddrPortFrom(fake, 443) {
		t.Fatalf("original destination: %v", s.dst)
	}

	u, err := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(DNSAddr4.As4()), Port: 53}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte("query"))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	if err != nil || string(buf[:n]) != "reply to 198.18.0.2:53: query" {
		t.Fatalf("udp: %v %q", err, buf[:n])
	}
}
