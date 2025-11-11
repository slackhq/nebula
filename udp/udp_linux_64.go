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

func (u *StdConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	for i := range msgs {
		buffers[i] = make([]byte, MTU)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{
			{Base: &buffers[i][0], Len: uint64(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, buffers, names
}

func (u *StdConn) PrepareWriteMessages4(n int) ([]rawMessage, []iovec, [][]byte) {
	msgs := make([]rawMessage, n)
	iovecs := make([]iovec, n)
	names := make([][]byte, n)

	for i := range msgs {
		names[i] = make([]byte, unix.SizeofSockaddrInet4)

		// Point to the iovec in the slice
		msgs[i].Hdr.Iov = &iovecs[i]
		msgs[i].Hdr.Iovlen = 1

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
	}

	return msgs, iovecs, names
}

func (u *StdConn) PrepareWriteMessages6(n int) ([]rawMessage, []iovec, [][]byte) {
	msgs := make([]rawMessage, n)
	iovecs := make([]iovec, n)
	names := make([][]byte, n)

	for i := range msgs {
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		// Point to the iovec in the slice
		msgs[i].Hdr.Iov = &iovecs[i]
		msgs[i].Hdr.Iovlen = 1

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
	}

	return msgs, iovecs, names
}
