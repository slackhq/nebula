//go:build !windows

package udp

import (
	"errors"
	"syscall"
)

// IsUnreachable reports whether a send failed because this host has no way to reach the destination from where it
// is now, rather than for something transient. Moving from a dual stack network to one without IPv6 turns every send
// to an IPv6 remote into one of these.
func IsUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, ErrInvalidIPv6RemoteForSocket)
}
