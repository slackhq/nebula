//go:build e2e_testing
// +build e2e_testing

package udp

import (
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/sirupsen/logrus"
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

	closed atomic.Bool
	l      *logrus.Logger
}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, _ bool, _ int) (Conn, error) {
	return &TesterConn{
		Addr:      netip.AddrPortFrom(ip, uint16(port)),
		RxPackets: make(chan *Packet, 10),
		TxPackets: make(chan *Packet, 10),
		l:         l,
	}, nil
}

// Send will place a UdpPacket onto the receive queue for nebula to consume
// this is an encrypted packet or a handshake message in most cases
// packets were transmitted from another nebula node, you can send them with Tun.Send
func (u *TesterConn) Send(packet *Packet) {
	if u.closed.Load() {
		return
	}

	h := &header.H{}
	if err := h.Parse(packet.Data); err != nil {
		panic(err)
	}
	if u.l.Level >= logrus.DebugLevel {
		u.l.WithField("header", h).
			WithField("udpAddr", packet.From).
			WithField("dataLen", len(packet.Data)).
			Debug("UDP receiving injected packet")
	}
	u.RxPackets <- packet
}

// Get will pull a UdpPacket from the transmit queue
// nebula meant to send this message on the network, it will be encrypted
// packets were ingested from the tun side (in most cases), you can send them with Tun.Send
func (u *TesterConn) Get(block bool) *Packet {
	if block {
		return <-u.TxPackets
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
	if u.closed.Load() {
		return io.ErrClosedPipe
	}

	p := &Packet{
		Data: make([]byte, len(b), len(b)),
		From: u.Addr,
		To:   addr,
	}

	copy(p.Data, b)
	u.TxPackets <- p
	return nil
}

func (u *TesterConn) ListenOut(r EncReader) {
	for {
		p, ok := <-u.RxPackets
		if !ok {
			return
		}
		r(p.From, p.Data)
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
	if u.closed.CompareAndSwap(false, true) {
		close(u.RxPackets)
		close(u.TxPackets)
	}
	return nil
}
