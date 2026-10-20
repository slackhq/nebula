//go:build !windows

package udp

import (
	"net"
	"syscall"
	"testing"
)

func TestIsUnreachable(t *testing.T) {
	wrap := func(err error) error { return &net.OpError{Op: "write", Net: "udp", Err: err} }

	for _, err := range []error{
		wrap(syscall.ENETUNREACH),
		wrap(syscall.EHOSTUNREACH),
		wrap(syscall.EADDRNOTAVAIL),
		wrap(syscall.EAFNOSUPPORT),
		ErrInvalidIPv6RemoteForSocket,
	} {
		if !IsUnreachable(err) {
			t.Errorf("IsUnreachable(%v) = false, want true", err)
		}
	}

	for _, err := range []error{
		nil,
		wrap(syscall.EPERM),
		wrap(syscall.ENOBUFS),
		wrap(syscall.EMSGSIZE),
		net.ErrClosed,
	} {
		if IsUnreachable(err) {
			t.Errorf("IsUnreachable(%v) = true, want false", err)
		}
	}
}
