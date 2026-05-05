//go:build (!linux || android) && !e2e_testing && !darwin
// +build !linux android
// +build !e2e_testing
// +build !darwin

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/config"
)

type GenericConn struct {
	*net.UDPConn
	l *slog.Logger
}

var _ Conn = &GenericConn{}

func NewGenericListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", net.JoinHostPort(ip.String(), fmt.Sprintf("%v", port)))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &GenericConn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (u *GenericConn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := u.UDPConn.WriteToUDPAddrPort(b, addr)
	return err
}

func (u *GenericConn) LocalAddr() (netip.AddrPort, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *GenericConn) ReloadConfig(c *config.C) {

}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *GenericConn) ListenOut(r EncReader) error {
	buffer := make([]byte, MTU)

	var lastRecvErr time.Time

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Dampen unexpected message warns to once per minute
			if lastRecvErr.IsZero() || time.Since(lastRecvErr) > time.Minute {
				lastRecvErr = time.Now()
				u.l.Warn("unexpected udp socket receive error", "error", err)
			}
			continue
		}

		r(netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()), buffer[:n])
	}
}

func (u *GenericConn) SupportsMultipleReaders() bool {
	return false
}

// EnablePathMTUDiscovery is implemented per-platform alongside Rebind, in
// udp_android.go / udp_bsd.go / udp_netbsd.go / udp_windows.go.

// controlFD invokes f with the underlying UDP socket file descriptor (or
// handle, on Windows). Used by platform files for setsockopt calls that the
// stdlib net.UDPConn does not expose directly.
func (u *GenericConn) controlFD(f func(fd uintptr) error) error {
	rc, err := u.UDPConn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = rc.Control(func(fd uintptr) {
		sockErr = f(fd)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// isV4Socket reports whether the local bind address looks like an IPv4 socket.
// Used by EnablePathMTUDiscovery to pick IPPROTO_IP vs IPPROTO_IPV6 socket
// options. Assumes pure-v4 or pure-v6 sockets; a dual-stack v6 socket bound to
// :: will be treated as v6 (correct: setting IPV6_DONTFRAG covers v4-mapped
// traffic too on most stacks).
func (u *GenericConn) isV4Socket() bool {
	la := u.UDPConn.LocalAddr()
	if la == nil {
		return false
	}
	ua, ok := la.(*net.UDPAddr)
	if !ok {
		return false
	}
	return ua.IP.To4() != nil
}
