//go:build !amd64 && !arm64

package checksum

import gvisorchecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"

// Checksum delegates to gvisor on architectures without a hand-written body.
func Checksum(buf []byte, initial uint16) uint16 {
	return gvisorchecksum.Checksum(buf, initial)
}
