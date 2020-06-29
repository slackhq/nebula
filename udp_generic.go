// +build !linux android

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type udpAddr struct {
	net.UDPAddr
}

type udpConn struct {
	*net.UDPConn
}

func NewUDPAddr(ip uint32, port uint16) *udpAddr {
	return &udpAddr{
		UDPAddr: net.UDPAddr{
			IP:   int2ip(ip),
			Port: int(port),
		},
	}
}

func NewUDPAddrFromString(s string) *udpAddr {
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return nil
	}

	port, _ := strconv.Atoi(p[1])
	return &udpAddr{
		UDPAddr: net.UDPAddr{
			IP:   net.ParseIP(p[0]),
			Port: port,
		},
	}
}

func NewListener(ip string, port int, multi bool) (*udpConn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &udpConn{UDPConn: uc}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (ua *udpAddr) Equals(t *udpAddr) bool {
	if t == nil || ua == nil {
		return t == nil && ua == nil
	}
	return ua.IP.Equal(t.IP) && ua.Port == t.Port
}

func (uc *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	_, err := uc.UDPConn.WriteToUDP(b, &addr.UDPAddr)
	return err
}

func (uc *udpConn) LocalAddr() (*udpAddr, error) {
	a := uc.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		return &udpAddr{UDPAddr: *v}, nil
	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *udpConn) reloadConfig(c *Config) {
	// TODO
}

type rawMessage struct {
	Len uint32
}

func (u *udpConn) ListenOut(f *Interface) {
	plaintext := make([]byte, mtu)
	buffer := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDP(buffer)
		if err != nil {
			l.WithError(err).Error("Failed to read packets")
			continue
		}

		udpAddr.UDPAddr = *rua
		f.readOutsidePackets(udpAddr, plaintext[:0], buffer[:n], header, fwPacket, nb)
	}
}

func udp2ip(addr *udpAddr) net.IP {
	return addr.IP
}

func udp2ipInt(addr *udpAddr) uint32 {
	return binary.BigEndian.Uint32(addr.IP.To4())
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
