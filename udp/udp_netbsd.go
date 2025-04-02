//go:build !e2e_testing
// +build !e2e_testing

package udp

// FreeBSD support is primarily implemented in udp_generic, besides NewListenConfig

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
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
