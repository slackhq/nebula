// +build e2e_testing

package nebula

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

type UdpPacket struct {
	ToIp     net.IP
	ToPort   uint16
	FromIp   net.IP
	FromPort uint16
	Data     []byte
}

func (u *UdpPacket) Copy() *UdpPacket {
	n := &UdpPacket{
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

type udpConn struct {
	addr *udpAddr

	rxPackets chan *UdpPacket // Packets to receive into nebula
	txPackets chan *UdpPacket // Packets transmitted outside by nebula

	l *logrus.Logger
}

func NewListener(l *logrus.Logger, ip string, port int, _ bool) (*udpConn, error) {
	return &udpConn{
		addr:      &udpAddr{net.ParseIP(ip), uint16(port)},
		rxPackets: make(chan *UdpPacket, 1),
		txPackets: make(chan *UdpPacket, 1),
		l:         l,
	}, nil
}

// Send will place a UdpPacket onto the receive queue for nebula to consume
// this is an encrypted packet or a handshake message in most cases
// packets were transmitted from another nebula node, you can send them with Tun.Send
func (u *udpConn) Send(packet *UdpPacket) {
	h := &Header{}
	if err := h.Parse(packet.Data); err != nil {
		panic(err)
	}
	u.l.WithField("header", h).
		WithField("udpAddr", fmt.Sprintf("%v:%v", packet.FromIp, packet.FromPort)).
		WithField("dataLen", len(packet.Data)).
		Info("UDP receiving injected packet")
	u.rxPackets <- packet
}

// Get will pull a UdpPacket from the transmit queue
// nebula meant to send this message on the network, it will be encrypted
// packets were ingested from the tun side (in most cases), you can send them with Tun.Send
func (u *udpConn) Get(block bool) *UdpPacket {
	if block {
		return <-u.txPackets
	}

	select {
	case p := <-u.txPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (u *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	p := &UdpPacket{
		Data:     make([]byte, len(b), len(b)),
		FromIp:   make([]byte, 16),
		FromPort: u.addr.Port,
		ToIp:     make([]byte, 16),
		ToPort:   addr.Port,
	}

	copy(p.Data, b)
	copy(p.ToIp, addr.IP.To16())
	copy(p.FromIp, u.addr.IP.To16())

	u.txPackets <- p
	return nil
}

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	ua := &udpAddr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()
	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for {
		p := <-u.rxPackets
		ua.Port = p.FromPort
		copy(ua.IP, p.FromIp.To16())
		f.readOutsidePackets(ua, plaintext[:0], p.Data, header, fwPacket, lhh, nb, q, conntrackCache.Get(u.l))
	}
}

func (u *udpConn) reloadConfig(*Config) {}

func NewUDPStatsEmitter(_ []*udpConn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func (u *udpConn) LocalAddr() (*udpAddr, error) {
	return u.addr, nil
}

func (u *udpConn) Rebind() error {
	return nil
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
