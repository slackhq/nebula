//go:build e2e_testing
// +build e2e_testing

package udp

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
)

type Packet struct {
	To   netip.AddrPort
	From netip.AddrPort
	Data []byte
}

func (u *Packet) Copy() *Packet {
	n := &Packet{
		To:   u.To,
		From: u.From,
		Data: make([]byte, len(u.Data)),
	}

	copy(n.Data, u.Data)
	return n
}

type TesterConn struct {
	Addr netip.AddrPort

	RxPackets chan *Packet // Packets to receive into nebula
	TxPackets chan *Packet // Packets transmitted outside by nebula

	// done is closed exactly once by Close. Senders select on it so they
	// never race with a channel close; readers exit when it fires. The
	// packet channels are intentionally never closed - that was the source
	// of `send on closed channel` panics when a WriteTo/Send from another
	// goroutine passed the close check and reached the send just after
	// Close ran.
	done      chan struct{}
	closeOnce sync.Once

	l *slog.Logger
}

func NewListener(l *slog.Logger, ip netip.Addr, port int, _ bool, _ int) (Conn, error) {
	return &TesterConn{
		Addr:      netip.AddrPortFrom(ip, uint16(port)),
		RxPackets: make(chan *Packet, 10),
		TxPackets: make(chan *Packet, 10),
		done:      make(chan struct{}),
		l:         l,
	}, nil
}

// Send will place a UdpPacket onto the receive queue for nebula to consume
// this is an encrypted packet or a handshake message in most cases
// packets were transmitted from another nebula node, you can send them with Tun.Send
func (u *TesterConn) Send(packet *Packet) {
	h := &header.H{}
	if err := h.Parse(packet.Data); err != nil {
		panic(err)
	}
	if u.l.Enabled(context.Background(), slog.LevelDebug) {
		u.l.Debug("UDP receiving injected packet",
			"header", h,
			"udpAddr", packet.From,
			"dataLen", len(packet.Data),
		)
	}
	select {
	case <-u.done:
	case u.RxPackets <- packet:
	}
}

// Get will pull a UdpPacket from the transmit queue
// nebula meant to send this message on the network, it will be encrypted
// packets were ingested from the tun side (in most cases), you can send them with Tun.Send
func (u *TesterConn) Get(block bool) *Packet {
	if block {
		select {
		case <-u.done:
			return nil
		case p := <-u.TxPackets:
			return p
		}
	}

	select {
	case p := <-u.TxPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (u *TesterConn) WriteTo(b []byte, addr netip.AddrPort) error {
	p := &Packet{
		Data: make([]byte, len(b), len(b)),
		From: u.Addr,
		To:   addr,
	}

	copy(p.Data, b)
	select {
	case <-u.done:
		return io.ErrClosedPipe
	case u.TxPackets <- p:
		return nil
	}
}

func (u *TesterConn) ListenOut(r EncReader) error {
	for {
		select {
		case <-u.done:
			return os.ErrClosed
		case p := <-u.RxPackets:
			r(p.From, p.Data)
		}
	}
}

func (u *TesterConn) ReloadConfig(*config.C) {}

func NewUDPStatsEmitter(_ []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func (u *TesterConn) LocalAddr() (netip.AddrPort, error) {
	return u.Addr, nil
}

func (u *TesterConn) SupportsMultipleReaders() bool {
	return false
}

func (u *TesterConn) Rebind() error {
	return nil
}

func (u *TesterConn) Close() error {
	u.closeOnce.Do(func() {
		close(u.done)
	})
	return nil
}
