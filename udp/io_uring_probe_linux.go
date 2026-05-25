//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"strings"

	"github.com/randomizedcoder/giouring"
	"golang.org/x/sys/unix"
)

// minIoUringKernelMajor / Minor gate enablement to the kernel line where
// io_uring core stabilised. Earlier kernels (5.1-5.5) had io_uring but with
// known issues around socket ops; 5.6 is the floor we treat as supported.
const (
	minIoUringKernelMajor = 5
	minIoUringKernelMinor = 6
)

// IoUringAvailable probes the running kernel for io_uring support of the two
// opcodes nebula needs (recvmsg, sendmsg). Returns false if the kernel is
// older than 5.6, if io_uring is unavailable, or if either opcode is missing
// from the IORING_REGISTER_PROBE response. Best-effort; on any error we
// conservatively return false so the caller falls back to recvmmsg/sendmmsg.
func IoUringAvailable() bool {
	if !kernelAtLeast(minIoUringKernelMajor, minIoUringKernelMinor) {
		return false
	}
	probe, err := giouring.GetProbe()
	if err != nil {
		return false
	}
	return probe.IsSupported(giouring.OpRecvmsg) && probe.IsSupported(giouring.OpSendmsg)
}

// kernelAtLeast reports whether `uname` reports a kernel version at least
// major.minor. parseRelease lives in udp_linux.go and is reused.
func kernelAtLeast(major, minor int) bool {
	var un unix.Utsname
	if err := unix.Uname(&un); err != nil {
		return false
	}
	rel := string(un.Release[:])
	if i := strings.IndexByte(rel, 0); i >= 0 {
		rel = rel[:i]
	}
	gotMajor, gotMinor := parseRelease(rel)
	if gotMajor > major {
		return true
	}
	return gotMajor == major && gotMinor >= minor
}
