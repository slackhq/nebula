package checksum

import (
	"golang.org/x/sys/cpu"
	gvisorchecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"
)

//go:noescape
func checksumAVX2(buf []byte, initial uint16) uint16

var hasAVX2 = cpu.X86.HasAVX2

// Checksum computes the RFC 1071 ones-complement sum of buf, seeded with
// initial. It is a drop-in replacement for gvisor's checksum.Checksum that
// dispatches to a hand-written AVX2 routine on amd64 CPUs that support it,
// falling back to gvisor's pure-Go implementation otherwise. The result
// matches gvisor's bit-for-bit for any buffer length and initial seed.
func Checksum(buf []byte, initial uint16) uint16 {
	if hasAVX2 {
		return checksumAVX2(buf, initial)
	}
	return gvisorchecksum.Checksum(buf, initial)
}
