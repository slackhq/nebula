//go:build e2e_testing
// +build e2e_testing

package udp

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

type Packet struct {
	ToIp     net.IP
	ToPort   uint16
	FromIp   net.IP
	FromPort uint16
	Data     []byte
}

func (u *Packet) Copy() *Packet {
	n := &Packet{
		ToIp:     make(net.IP, len(u.ToIp)),
		ToPort:   u.ToPort,
		FromIp:   make(net.IP, len(u.FromIp)),
		FromPort: u.FromPort,
		Data:     make([]byte, len(u.Data)),
	}

	copy(n.ToIp, u.ToIp)
	copy(n.FromIp, u.FromIp)
	copy(n.Data, u.Data)
	return n
}

type TesterConn struct {
	Addr *Addr

	RxPackets chan *Packet // Packets to receive into nebula
	TxPackets chan *Packet // Packets transmitted outside by nebula

	closed atomic.Bool
	l      *logrus.Logger
}

func NewListener(l *logrus.Logger, ip net.IP, port int, _ bool, _ int) (Conn, error) {
	return &TesterConn{
		Addr:      &Addr{ip, uint16(port)},
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
			WithField("udpAddr", fmt.Sprintf("%v:%v", packet.FromIp, packet.FromPort)).
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

func (u *TesterConn) WriteTo(b []byte, addr *Addr) error {
	if u.closed.Load() {
		return io.ErrClosedPipe
	}

	p := &Packet{
		Data:     make([]byte, len(b), len(b)),
		FromIp:   make([]byte, 16),
		FromPort: u.Addr.Port,
		ToIp:     make([]byte, 16),
		ToPort:   addr.Port,
	}

	copy(p.Data, b)
	copy(p.ToIp, addr.IP.To16())
	copy(p.FromIp, u.Addr.IP.To16())

	u.TxPackets <- p
	return nil
}

func (u *TesterConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	ua := &Addr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	for {
		p, ok := <-u.RxPackets
		if !ok {
			return
		}
		ua.Port = p.FromPort
		copy(ua.IP, p.FromIp.To16())
		r(ua, plaintext[:0], p.Data, h, fwPacket, lhf, nb, q, cache.Get(u.l))
	}
}

func (u *TesterConn) ReloadConfig(*config.C) {}

func NewUDPStatsEmitter(_ []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func (u *TesterConn) LocalAddr() (*Addr, error) {
	return u.Addr, nil
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
