//go:build !e2e_testing
// +build !e2e_testing

package udp

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
// Android is Linux underneath, so we use IP_PMTUDISC_PROBE (kernel sets DF but
// does not consume incoming ICMP frag-needed for its PMTU cache; the manager
// drives discovery via authenticated probes).
func (u *GenericConn) EnablePathMTUDiscovery() error {
	v4 := u.isV4Socket()
	return u.controlFD(func(fd uintptr) error {
		if v4 {
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		}
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	})
}
