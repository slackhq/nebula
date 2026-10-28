//go:build !windows

package udp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// getV6Only reads IPV6_V6ONLY from an IPv6 socket
func getV6Only(rc syscall.RawConn) (bool, error) {
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		v, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
	}); err != nil {
		return false, err
	}
	return v != 0, serr
}
