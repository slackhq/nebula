//// +build !linux android
//
//// udp_generic implements the nebula UDP interface in pure Go stdlib. This
//// means it can be used on platforms like Darwin and Windows.
//
package udp

//
//import (
//	"context"
//	"fmt"
//	"net"
//
//	"github.com/sirupsen/logrus"
//	"github.com/slackhq/nebula"
//)
//
//type genericConn struct {
//	*net.UDPConn
//	l logrus.Logger
//}
//
//func NewListener(ip string, port int, multi bool) (*genericConn, error) {
//	lc := newListenConfig(multi)
//	pc, err := lc.ListenPacket(context.TODO(), "udp", fmt.Sprintf("%s:%d", ip, port))
//	if err != nil {
//		return nil, err
//	}
//	if uc, ok := pc.(*net.UDPConn); ok {
//		return &genericConn{UDPConn: uc}, nil
//	}
//	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
//}
//
//func (gc *genericConn) WriteTo(b []byte, addr *Addr) error {
//	//TODO: Maybe we just ditch our custom udpAddr entirely
//	_, err := gc.UDPConn.WriteToUDP(b, &net.UDPAddr{IP: addr.IP, Port: int(addr.Port)})
//	return err
//}
//
//func (gc *genericConn) LocalAddr() (*Addr, error) {
//	a := gc.UDPConn.LocalAddr()
//
//	switch v := a.(type) {
//	case *net.UDPAddr:
//		addr := &Addr{IP: make([]byte, len(v.IP))}
//		copy(addr.IP, v.IP)
//		addr.Port = uint16(v.Port)
//		return addr, nil
//
//	default:
//		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
//	}
//}
//
//func (gc *genericConn) reloadConfig(c *nebula.Config) {
//	// TODO
//}
//
//func NewUDPStatsEmitter(udpConns []*udpConn) func() {
//	// No UDP stats for non-linux
//	return func() {}
//}
//
//type rawMessage struct {
//	Len uint32
//}
//
//func (gc *genericConn) ListenOut(r EncReader, q int) {
//	plaintext := make([]byte, mtu)
//	buffer := make([]byte, mtu)
//	header := &nebula.Header{}
//	fwPacket := &nebula.FirewallPacket{}
//	udpAddr := &Addr{IP: make([]byte, 16)}
//	nb := make([]byte, 12, 12)
//
//	lhh := f.lightHouse.NewRequestHandler()
//
//	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)
//
//	for {
//		// Just read one packet at a time
//		n, rua, err := gc.ReadFromUDP(buffer)
//		if err != nil {
//			gc.l.WithError(err).Error("Failed to read packets")
//			continue
//		}
//
//		udpAddr.IP = rua.IP
//		udpAddr.Port = uint16(rua.Port)
//		r(udpAddr, plaintext[:0], buffer[:n], header, fwPacket, lhh, nb, q, conntrackCache.Get())
//	}
//}
