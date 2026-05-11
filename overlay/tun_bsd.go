//go:build (darwin || ios || freebsd || openbsd || netbsd) && !e2e_testing

package overlay

import (
	"fmt"
	"syscall"
)

// StampTunPrefix writes the 4-byte AF_INET / AF_INET6 protocol-family marker into buf[0:4] in place,
// picking the family from the first byte of the IP packet at buf[4].
func StampTunPrefix(buf []byte) error {
	if len(buf) < 5 {
		return fmt.Errorf("tun write buffer too small for prefix")
	}
	ipVer := buf[4] >> 4
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	switch ipVer {
	case 4:
		buf[3] = syscall.AF_INET
	case 6:
		buf[3] = syscall.AF_INET6
	default:
		return fmt.Errorf("unable to determine IP version from packet")
	}
	return nil
}
