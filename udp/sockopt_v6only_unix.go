//go:build !windows

package udp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getV6Only reads IPV6_V6ONLY from an IPv6 socket
func getV6Only(fd uintptr) (bool, error) {
	v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
	if err != nil {
		return false, fmt.Errorf("unable to read IPV6_V6ONLY: %w", err)
	}
	return v != 0, nil
}
