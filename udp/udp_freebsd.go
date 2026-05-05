//go:build freebsd && !e2e_testing
// +build freebsd,!e2e_testing

package udp

import (
	"golang.org/x/sys/unix"
)

// EnablePathMTUDiscovery sets the don't-fragment bit on outbound packets.
// FreeBSD exposes IP_DONTFRAG (v4) and IPV6_DONTFRAG (v6) in golang.org/x/sys/unix.
// Unlike Linux, BSDs don't have an explicit "don't consume incoming ICMP
// frag-needed" knob for unconnected UDP sockets; the kernel's PMTU cache will
// be updated from ICMP, which is benign for our usage (the cache only affects
// what EMSGSIZE gets surfaced for; the manager drives its own discovery via
// authenticated probes).
func (u *GenericConn) EnablePathMTUDiscovery() error {
	v4 := u.isV4Socket()
	return u.controlFD(func(fd uintptr) error {
		if v4 {
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		}
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	})
}
