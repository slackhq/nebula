//go:build (!linux || android) && !e2e_testing
// +build !linux android
// +build !e2e_testing

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package udp

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

type Conn struct {
	*net.UDPConn
	l *logrus.Logger
}

func NewListener(l *logrus.Logger, ip string, port int, multi bool, batch int) (*Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &Conn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (uc *Conn) WriteTo(b []byte, addr *Addr) error {
	_, err := uc.UDPConn.WriteToUDP(b, &net.UDPAddr{IP: addr.IP, Port: int(addr.Port)})
	return err
}

func (uc *Conn) LocalAddr() (*Addr, error) {
	a := uc.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr := &Addr{IP: make([]byte, len(v.IP))}
		copy(addr.IP, v.IP)
		addr.Port = uint16(v.Port)
		return addr, nil

	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *Conn) ReloadConfig(c *config.C) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []*Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	udpAddr := &Addr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDP(buffer)
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		udpAddr.IP = rua.IP
		udpAddr.Port = uint16(rua.Port)
		r(udpAddr, nil, plaintext[:0], buffer[:n], h, fwPacket, lhf, nb, q, cache.Get(u.l))
	}
}
