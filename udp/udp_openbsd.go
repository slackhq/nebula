//go:build openbsd && !e2e_testing
// +build openbsd,!e2e_testing

package udp

import (
	"golang.org/x/sys/unix"
)

// EnablePathMTUDiscovery sets the don't-fragment bit on outbound packets.
// OpenBSD exposes IPV6_DONTFRAG via golang.org/x/sys/unix but the kernel does
// not provide a socket-level knob for setting DF on v4 UDP. The only IP-layer
// constant exposed is IP_DF, which is the wire header flag, not a sockopt.
// quic-go skips OpenBSD for the same reason. So v4 sockets stay at nebula's
// historical behavior (kernel may fragment); v6 gets DF.
func (u *GenericConn) EnablePathMTUDiscovery() error {
	if u.isV4Socket() {
		return nil
	}
	return u.controlFD(func(fd uintptr) error {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	})
}
