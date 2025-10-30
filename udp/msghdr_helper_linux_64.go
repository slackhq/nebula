//go:build linux && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || s390x || riscv64 || loong64) && !android && !e2e_testing
// +build linux
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le s390x riscv64 loong64
// +build !android
// +build !e2e_testing

package udp

import "golang.org/x/sys/unix"

func controllen(n int) uint64 {
	return uint64(n)
}

func setCmsgLen(h *unix.Cmsghdr, n int) {
	h.Len = uint64(unix.CmsgLen(n))
}
