// +build !linux android
// +build !e2e_testing

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package nebula

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

type udpConn struct {
	*net.UDPConn
	l *logrus.Logger
}

func NewListener(l *logrus.Logger, ip string, port int, multi bool) (*udpConn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &udpConn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (uc *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	_, err := uc.UDPConn.WriteToUDP(b, &net.UDPAddr{IP: addr.IP, Port: int(addr.Port)})
	return err
}

func (uc *udpConn) LocalAddr() (*udpAddr, error) {
	a := uc.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr := &udpAddr{IP: make([]byte, len(v.IP))}
		copy(addr.IP, v.IP)
		addr.Port = uint16(v.Port)
		return addr, nil

	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *udpConn) reloadConfig(c *Config) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []*udpConn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	buffer := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()

	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDP(buffer)
		if err != nil {
			f.l.WithError(err).Error("Failed to read packets")
			continue
		}

		udpAddr.IP = rua.IP
		udpAddr.Port = uint16(rua.Port)
		f.readOutsidePackets(udpAddr, plaintext[:0], buffer[:n], header, fwPacket, lhh, nb, q, conntrackCache.Get(f.l))
	}
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
