// +build linux
// +build 386 amd64p32 arm mips mipsle
// +build !android

package nebula

import "unsafe"

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

func (u *udpConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	for i := range msgs {
		buffers[i] = make([]byte, mtu)
		names[i] = make([]byte, 0x1c) //TODO = sizeofSockaddrInet6

		//TODO: this is still silly, no need for an array
		vs := []iovec{
			{Base: (*byte)(unsafe.Pointer(&buffers[i][0])), Len: uint32(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint32(len(vs))

		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&names[i][0]))
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, buffers, names
}
