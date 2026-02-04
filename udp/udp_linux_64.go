//go:build linux && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || s390x || riscv64 || loong64) && !android && !e2e_testing
// +build linux
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le s390x riscv64 loong64
// +build !android
// +build !e2e_testing

package udp

import (
	"golang.org/x/sys/unix"
)

type iovec struct {
	Base *byte
	Len  uint64
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Pad0       [4]byte
	Iov        *iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	Pad1       [4]byte
}

type rawMessage struct {
	Hdr  msghdr
	Len  uint32
	Pad0 [4]byte
}

func (u *StdConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)
	controls := make([][]byte, n)

	// Use larger buffers if GRO is enabled to hold coalesced packets
	bufSize := MTU
	if u.groSupported {
		bufSize = groMaxPacketSize
	}

	// Control buffer size for receiving UDP_GRO segment size
	controlSize := 0
	if u.groSupported {
		controlSize = unix.CmsgSpace(2) // space for uint16 segment size
	}

	for i := range msgs {
		buffers[i] = make([]byte, bufSize)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{
			{Base: &buffers[i][0], Len: uint64(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))

		// Set up control message buffer for GRO
		if controlSize > 0 {
			controls[i] = make([]byte, controlSize)
			msgs[i].Hdr.Control = &controls[i][0]
			msgs[i].Hdr.Controllen = uint64(controlSize)
		}
	}

	return msgs, buffers, names, controls
}

func setIovecBase(iov *iovec, base *byte) {
	iov.Base = base
}

func setIovecLen(iov *iovec, l int) {
	iov.Len = uint64(l)
}

func setMsghdrIovlen(hdr *msghdr, l int) {
	hdr.Iovlen = uint64(l)
}

func setMsghdrControllen(hdr *msghdr, l int) {
	hdr.Controllen = uint64(l)
}

func getMsghdrControllen(hdr *msghdr) int {
	return int(hdr.Controllen)
}
