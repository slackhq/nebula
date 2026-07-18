//go:build linux && (386 || amd64p32 || arm || mips || mipsle) && !android && !e2e_testing
// +build linux
// +build 386 amd64p32 arm mips mipsle
// +build !android
// +build !e2e_testing

package udp

import (
	"golang.org/x/sys/unix"
)

type iovec struct {
	Base *byte
	Len  uint32
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *iovec
	Iovlen     uint32
	Control    *byte
	Controllen uint32
	Flags      int32
}

type rawMessage struct {
	Hdr msghdr
	Len uint32
}

func setIovLen(v *iovec, n int) {
	v.Len = uint32(n)
}

func setMsgIovlen(m *msghdr, n int) {
	m.Iovlen = uint32(n)
}

func setMsgControllen(m *msghdr, n int) {
	m.Controllen = uint32(n)
}

func setCmsgLen(h *unix.Cmsghdr, n int) {
	h.Len = uint32(n)
}
