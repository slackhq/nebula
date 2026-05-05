//go:build !e2e_testing
// +build !e2e_testing

package udp

// FreeBSD support is primarily implemented in udp_generic, besides NewListenConfig

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"log/slog"

	"golang.org/x/sys/unix"
)

func NewListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	return NewGenericListener(l, ip, port, multi, batch)
}

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				var controlErr error
				err := c.Control(func(fd uintptr) {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						controlErr = fmt.Errorf("SO_REUSEPORT failed: %v", err)
						return
					}
				})
				if err != nil {
					return err
				}
				if controlErr != nil {
					return controlErr
				}
			}
			return nil
		},
	}
}

func (u *GenericConn) Rebind() error {
	return nil
}

// EnablePathMTUDiscovery sets the don't-fragment bit on outbound packets.
// NetBSD exposes IPV6_DONTFRAG via golang.org/x/sys/unix but the kernel does
// not provide a socket-level knob for setting DF on v4 UDP. The only IP-layer
// constant exposed is IP_DF, which is the wire header flag, not a sockopt.
// quic-go skips NetBSD for the same reason. So v4 sockets stay at nebula's
// historical behavior (kernel may fragment); v6 gets DF.
func (u *GenericConn) EnablePathMTUDiscovery() error {
	if u.isV4Socket() {
		return nil
	}
	return u.controlFD(func(fd uintptr) error {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	})
}
