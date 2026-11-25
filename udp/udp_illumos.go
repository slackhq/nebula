//go:build illumos && !e2e_testing
// +build illumos,!e2e_testing

package udp

// illumos support is implemented in udp_generic, besides NewListenConfig and Rebind.

import (
	"errors"
	"log/slog"
	"net"
	"syscall"
)

func NewListener(l *slog.Logger, s Settings) (Conn, error) {
	return NewGenericListener(l, s)
}

// NewListenConfig returns a plain listen config. SO_REUSEPORT load balancing across
// several sockets is not relied on here, so more than one listen routine is refused.
func NewListenConfig(multi bool) net.ListenConfig {
	if multi {
		return net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return errors.New("multiple listen routines are not supported on illumos, set routines: 1")
			},
		}
	}
	return net.ListenConfig{}
}

func (u *GenericConn) Rebind() error {
	return nil
}
