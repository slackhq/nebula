package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/overlay"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

type Service struct {
	control *nebula.Control
	ipstack *stack.Stack

	// done is closed once the forwarding goroutines have exited and the
	// netstack is torn down, at which point err holds the first fatal error.
	done chan struct{}
	err  error

	mu struct {
		sync.Mutex

		closed    bool
		listeners map[uint16]*tcpListener
	}
}

func New(control *nebula.Control) (_ *Service, reterr error) {
	// Check this before Start so a failure doesn't leave a running nebula
	device, ok := control.Device().(*overlay.UserDevice)
	if !ok {
		return nil, errors.New("must be using user device")
	}

	err := control.Start()
	if err != nil {
		return nil, err
	}

	// Anything that fails after a successful Start must tear nebula back down
	defer func() {
		if reterr != nil {
			control.Stop()
		}
	}()

	ctx := control.Context()
	eg, ctx := errgroup.WithContext(ctx)
	s := Service{
		control: control,
	}
	s.mu.listeners = map[uint16]*tcpListener{}

	s.ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	// The teardown goroutine only owns the stack once New succeeds
	defer func() {
		if reterr != nil {
			s.ipstack.Destroy()
		}
	}()
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := s.ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	linkEP := channel.New( /*size*/ 512 /*mtu*/, 1280, "")
	if tcpipProblem := s.ipstack.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", tcpipProblem)
	}
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0x00, 0x00, 0x00, 0x00}), tcpip.MaskFrom(strings.Repeat("\x00", 4)))
	s.ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
	})

	ipNet := device.Networks()
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(ipNet[0].Addr().AsSlice()).WithPrefix(),
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := s.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint, // zero value default
		ConfigType: stack.AddressConfigStatic,  // zero value default
	}); err != nil {
		return nil, fmt.Errorf("error creating IP: %s", err)
	}

	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(s.ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, s.tcpHandler)
	s.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	reader, writer := device.Pipe()

	go func() {
		<-ctx.Done()
		reader.Close()
		writer.Close()
	}()

	// create Goroutines to forward packets between Nebula and Gvisor
	eg.Go(func() error {
		buf := make([]byte, header.IPv4MaximumHeaderSize+header.IPv4MaximumPayloadSize)
		for {
			// this will read exactly one packet
			n, err := reader.Read(buf)
			if err != nil {
				// An error after shutdown began is noise from the device pipes
				// closing, anything else is fatal and must stop nebula too
				if ctx.Err() != nil {
					return nil
				}
				s.control.Stop()
				return err
			}
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buf[:n])),
			})
			linkEP.InjectInbound(header.IPv4ProtocolNumber, packetBuf)

			if ctx.Err() != nil {
				return nil
			}
		}
	})
	eg.Go(func() error {
		for {
			packet := linkEP.ReadContext(ctx)
			if packet == nil {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			bufView := packet.ToView()
			if _, err := bufView.WriteTo(writer); err != nil {
				// Same shutdown noise handling as the inbound reader
				if ctx.Err() != nil {
					return nil
				}
				s.control.Stop()
				return err
			}
			bufView.Release()
		}
	})

	// Add the nebula wait function to the group so a fatal reader error
	// propagates out through errgroup.Wait().
	eg.Go(func() error {
		return control.Wait()
	})

	// Tear down here rather than in Close so it also happens when nebula stops
	// on its own. The forwarding goroutines must exit before the stack they feed
	// is destroyed.
	s.done = make(chan struct{})
	go func() {
		s.err = eg.Wait()
		s.closeListeners()
		// Destroy aborts the endpoints that exist when it starts, then waits on
		// every endpoint, so a Dial registering in between would hold Wait until
		// its connect timed out. Without the NIC new dials fail route lookup.
		// RemoveNIC also closes linkEP.
		_ = s.ipstack.RemoveNIC(nicID)
		s.ipstack.Destroy()
		close(s.done)
	}()

	return &s, nil
}

func getProtocolNumber(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

// DialContext dials the provided address.
func (s *Service) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		fullAddr := tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFromSlice(addr.IP),
			Port: uint16(addr.Port),
		}
		num := getProtocolNumber(addr.AddrPort().Addr())
		return gonet.DialUDP(s.ipstack, nil, &fullAddr, num)
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		fullAddr := tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFromSlice(addr.IP),
			Port: uint16(addr.Port),
		}
		num := getProtocolNumber(addr.AddrPort().Addr())
		return gonet.DialContextTCP(ctx, s.ipstack, fullAddr, num)
	default:
		return nil, fmt.Errorf("unknown network type: %s", network)
	}
}

// Dial dials the provided address
func (s *Service) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// Listen listens on the provided address. Currently only TCP with wildcard
// addresses are supported.
func (s *Service) Listen(network, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("only tcp is supported")
	}
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	if addr.IP != nil && !bytes.Equal(addr.IP, []byte{0, 0, 0, 0}) {
		return nil, fmt.Errorf("only wildcard address supported, got %q %v", address, addr.IP)
	}
	if addr.Port == 0 {
		return nil, errors.New("specific port required, got 0")
	}
	if addr.Port < 0 || addr.Port >= math.MaxUint16 {
		return nil, fmt.Errorf("invalid port %d", addr.Port)
	}
	port := uint16(addr.Port)

	l := &tcpListener{
		port:   port,
		s:      s,
		addr:   addr,
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mu.closed {
		return nil, net.ErrClosed
	}
	if _, ok := s.mu.listeners[port]; ok {
		return nil, fmt.Errorf("already listening on port %d", port)
	}
	s.mu.listeners[port] = l

	return l, nil
}

// Wait blocks until the service has fully stopped, either via Close or a fatal
// error, and returns the first fatal error if there was one.
func (s *Service) Wait() error {
	<-s.done
	return s.err
}

// Close closes all listeners and stops nebula. Use Wait to block until
// shutdown has completed.
func (s *Service) Close() error {
	s.closeListeners()
	s.control.Stop()
	return nil
}

// closeListeners unblocks pending Accept calls and rejects new listeners.
func (s *Service) closeListeners() {
	// Every caller closes every listener rather than returning early once
	// closed is set, so none returns while another is still closing them.
	s.mu.Lock()
	s.mu.closed = true
	listeners := make([]*tcpListener, 0, len(s.mu.listeners))
	for _, l := range s.mu.listeners {
		listeners = append(listeners, l)
	}
	s.mu.Unlock()

	for _, l := range listeners {
		_ = l.Close()
	}
}

func (s *Service) tcpHandler(r *tcp.ForwarderRequest) {
	endpointID := r.ID()

	s.mu.Lock()
	l, ok := s.mu.listeners[endpointID.LocalPort]
	s.mu.Unlock()
	if !ok {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("got error creating endpoint %q", err)
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)

	// The handoff blocks until Accept is called, so it must not hold s.mu or a
	// listener nobody accepts from stalls every other port.
	conn := gonet.NewTCPConn(&wq, ep)
	select {
	case l.accept <- conn:
	case <-l.closed:
		_ = conn.Close()
	}
}
