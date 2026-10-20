package udp

import (
	"errors"

	"golang.org/x/sys/windows"
)

// IsUnreachable reports whether a send failed because this host has no way to reach the destination from where it
// is now, rather than for something transient. Moving from a dual stack network to one without IPv6 turns every send
// to an IPv6 remote into one of these.
func IsUnreachable(err error) bool {
	return errors.Is(err, windows.WSAENETUNREACH) ||
		errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAEADDRNOTAVAIL) ||
		errors.Is(err, windows.WSAEAFNOSUPPORT) ||
		errors.Is(err, ErrInvalidIPv6RemoteForSocket)
}
