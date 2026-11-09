package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

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
	"gvisor.dev/gvisor/pkg/waiter"
)

// Device is the packet interface of a TUN device (wireguard-go's tun.Device
// satisfies it).
type Device interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	BatchSize() int
	MTU() (int, error)
	Close() error
}

// Handlers receive what the stack recovers from IP packets.
type Handlers struct {
	// TCP gets each accepted connection; LocalAddr is the original destination.
	TCP func(c net.Conn, src, dst netip.AddrPort)
	// UDP gets each new flow; returning false drops it.
	UDP func(c *gonet.UDPConn, src, dst netip.AddrPort) bool
}

// Offset is the headroom kept in front of every packet for the device
// (utun's 4-byte family header, Linux virtio-net headers).
const Offset = 16

// Stack is a gVisor netstack attached to a TUN device.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	dev    Device
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// NewStack starts a netstack over dev.
func NewStack(dev Device, h Handlers) (*Stack, error) {
	mtu, err := dev.MTU()
	if err != nil {
		return nil, err
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	if h.TCP != nil {
		fwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
			id := r.ID()
			var wq waiter.Queue
			e, terr := r.CreateEndpoint(&wq)
			if terr != nil {
				r.Complete(true)
				return
			}
			r.Complete(false)
			e.SocketOptions().SetKeepAlive(true)
			c := gonet.NewTCPConn(&wq, e)
			go h.TCP(c, addrPort(id.RemoteAddress, id.RemotePort), addrPort(id.LocalAddress, id.LocalPort))
		})
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	}
	if h.UDP != nil {
		fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
			id := r.ID()
			src, dst := addrPort(id.RemoteAddress, id.RemotePort), addrPort(id.LocalAddress, id.LocalPort)
			var wq waiter.Queue
			e, terr := r.CreateEndpoint(&wq)
			if terr != nil {
				return false
			}
			c := gonet.NewUDPConn(&wq, e)
			go func() {
				if !h.UDP(c, src, dst) {
					c.Close()
				}
			}()
			return true
		})
		s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, dev: dev, cancel: cancel}
	st.wg.Add(2)
	go st.inbound(mtu)
	go st.outbound(ctx)
	return st, nil
}

func (st *Stack) inbound(mtu int) {
	defer st.wg.Done()
	batch := st.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, Offset+mtu+64)
	}
	sizes := make([]int, batch)
	for {
		n, err := st.dev.Read(bufs, sizes, Offset)
		for i := 0; i < n; i++ {
			data := bufs[i][Offset : Offset+sizes[i]]
			if len(data) == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch data[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
			st.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) || isClosed(err) {
				return
			}
			continue
		}
	}
}

func isClosed(err error) bool {
	return err != nil && (errors.Is(err, net.ErrClosed) || err.Error() == "file already closed" || err.Error() == "device closed")
}

func (st *Stack) outbound(ctx context.Context) {
	defer st.wg.Done()
	for {
		pkt := st.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		b := make([]byte, Offset+v.Size())
		copy(b[Offset:], v.AsSlice())
		v.Release()
		pkt.DecRef()
		if _, err := st.dev.Write([][]byte{b}, Offset); err != nil && isClosed(err) {
			return
		}
	}
}

// Close stops the stack and closes the device.
func (st *Stack) Close() {
	st.cancel()
	st.dev.Close()
	st.ep.Close()
	st.s.Close()
	st.wg.Wait()
}
