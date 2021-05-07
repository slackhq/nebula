// +build e2e_testing

package udp

import (
	"fmt"
	"net"

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

type Conn struct {
	Addr *Addr

	RxPackets chan *Packet // Packets to receive into nebula
	TxPackets chan *Packet // Packets transmitted outside by nebula

	l *logrus.Logger
}

func NewListener(l *logrus.Logger, ip string, port int, _ int) (*Conn, error) {
	return &Conn{
		Addr:      &Addr{net.ParseIP(ip), uint16(port)},
		RxPackets: make(chan *Packet, 1),
		TxPackets: make(chan *Packet, 1),
		l:         l,
	}, nil
}

// Send will place a UdpPacket onto the receive queue for nebula to consume
// this is an encrypted packet or a handshake message in most cases
// packets were transmitted from another nebula node, you can send them with Tun.Send
func (u *Conn) Send(packet *Packet) {
	h := &header.H{}
	if err := h.Parse(packet.Data); err != nil {
		panic(err)
	}
	u.l.WithField("header", h).
		WithField("udpAddr", fmt.Sprintf("%v:%v", packet.FromIp, packet.FromPort)).
		WithField("dataLen", len(packet.Data)).
		Info("UDP receiving injected packet")
	u.RxPackets <- packet
}

// Get will pull a UdpPacket from the transmit queue
// nebula meant to send this message on the network, it will be encrypted
// packets were ingested from the tun side (in most cases), you can send them with Tun.Send
func (u *Conn) Get(block bool) *Packet {
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

func (u *Conn) WriteTo(b []byte, addr *Addr) error {
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

func (u *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	ua := &Addr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	for {
		p := <-u.RxPackets
		ua.Port = p.FromPort
		copy(ua.IP, p.FromIp.To16())
		r(ua, plaintext[:0], p.Data, h, fwPacket, lhf, nb, q, cache.Get(u.l))
	}
}

func (u *Conn) ReloadConfig(*config.C) {}

func NewUDPStatsEmitter(_ []*Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func (u *Conn) LocalAddr() (*Addr, error) {
	return u.Addr, nil
}

func (u *Conn) Rebind() error {
	return nil
}
