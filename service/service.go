package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/util"
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
	l       *logrus.Logger
	eg      *errgroup.Group
	control *nebula.Control
	ipstack *stack.Stack

	mu struct {
		sync.Mutex

		listeners map[uint16]*tcpListener
	}
}

func New(control *nebula.Control) (*Service, error) {
	control.Start()

	ctx := control.Context()
	eg, ctx := errgroup.WithContext(ctx)
	s := Service{
		l:       control.GetLogger(),
		eg:      eg,
		control: control,
	}
	s.mu.listeners = map[uint16]*tcpListener{}

	device, ok := control.Device().(*overlay.UserDevice)
	if !ok {
		return nil, errors.New("must be using user device")
	}

	s.ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
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

	nebula_tun_reader, nebula_tun_writer := device.Pipe()

	// create Goroutines to forward packets between Nebula and Gvisor
	eg.Go(func() error {
		defer linkEP.Close()
		for {
			select {
			case <-ctx.Done():
				return nil
			case view, ok := <-nebula_tun_reader:
				if !ok {
					return nil
				}
				packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithView(view),
				})
				linkEP.InjectInbound(header.IPv4ProtocolNumber, packetBuf)
			}
		}
	})
	eg.Go(func() error {
		defer close(nebula_tun_writer)
		for {
			packet := linkEP.ReadContext(ctx)
			if packet == nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				continue
			}
			nebula_tun_writer <- packet.ToView()
		}
	})

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

func (s *Service) DialUDP(address string) (*gonet.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	fullAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.IP),
		Port: uint16(addr.Port),
	}

	return gonet.DialUDP(s.ipstack, nil, &fullAddr, ipv4.ProtocolNumber)
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
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.mu.listeners[port]; ok {
		return nil, fmt.Errorf("already listening on port %d", port)
	}
	s.mu.listeners[port] = l

	return l, nil
}

func (s *Service) ListenUDP(address string) (*gonet.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return gonet.DialUDP(s.ipstack, &tcpip.FullAddress{
		NIC:      nicID,
		Addr:     tcpip.AddrFromSlice(addr.IP),
		Port:     uint16(addr.Port),
		LinkAddr: "",
	}, nil, ipv4.ProtocolNumber)
}

func (s *Service) Wait() error {
	err := s.eg.Wait()

	s.ipstack.Destroy()

	return err
}

func (s *Service) Close() error {
	s.control.Stop()
	return nil
}

func (s *Service) CloseAndWait() error {
	s.Close()
	if err := s.Wait(); err != nil {
		if errors.Is(err, os.ErrClosed) ||
			errors.Is(err, io.EOF) ||
			errors.Is(err, context.Canceled) {
			s.l.Debugf("Stop of nebula service returned: %v", err)
			return nil
		} else {
			util.LogWithContextIfNeeded("Unclean stop", err, s.l)
			return err
		}
	}

	return nil
}

func (s *Service) tcpHandler(r *tcp.ForwarderRequest) {
	endpointID := r.ID()

	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.mu.listeners[endpointID.LocalPort]
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

	conn := gonet.NewTCPConn(&wq, ep)
	l.accept <- conn
}
