// +build linux
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le s390x
// +build !android

package nebula

import "unsafe"

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

func (u *udpConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	for i := range msgs {
		buffers[i] = make([]byte, mtu)
		names[i] = make([]byte, 0x1c) //TODO = sizeofSockaddrInet6

		//TODO: this is still silly, no need for an array
		vs := []iovec{
			{Base: (*byte)(unsafe.Pointer(&buffers[i][0])), Len: uint64(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&names[i][0]))
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, buffers, names
}
