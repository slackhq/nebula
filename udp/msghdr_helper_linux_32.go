//go:build linux && (386 || amd64p32 || arm || mips || mipsle) && !android && !e2e_testing
// +build linux
// +build 386 amd64p32 arm mips mipsle
// +build !android
// +build !e2e_testing

package udp

import "golang.org/x/sys/unix"

func controllen(n int) uint32 {
	return uint32(n)
}

func setCmsgLen(h *unix.Cmsghdr, n int) {
	h.Len = uint32(unix.CmsgLen(n))
}

func setIovecLen(v *unix.Iovec, n int) {
	v.Len = uint32(n)
}

func setMsghdrIovlen(m *unix.Msghdr, n int) {
	m.Iovlen = uint32(n)
}
