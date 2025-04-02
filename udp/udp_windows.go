//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/sirupsen/logrus"
)

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	if multi {
		//NOTE: Technically we can support it with RIO but it wouldn't be at the socket level
		// The udp stack would need to be reworked to hide away the implementation differences between
		// Windows and Linux
		return nil, fmt.Errorf("multiple udp listeners not supported on windows")
	}

	rc, err := NewRIOListener(l, ip, port)
	if err == nil {
		return rc, nil
	}

	l.WithError(err).Error("Falling back to standard udp sockets")
	return NewGenericListener(l, ip, port, multi, batch)
}

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				// There is no way to support multiple listeners safely on Windows:
				// https://docs.microsoft.com/en-us/windows/desktop/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
				return fmt.Errorf("multiple udp listeners not supported on windows")
			}
			return nil
		},
	}
}

func (u *GenericConn) Rebind() error {
	return nil
}
