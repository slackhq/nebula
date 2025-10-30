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

func (u *StdConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte, [][]byte) {
	controlLen := int(u.controlLen.Load())

	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	var controls [][]byte
	if controlLen > 0 {
		controls = make([][]byte, n)
	}

	for i := range msgs {
		size := MTU
		if defaultGROReadBufferSize > size {
			size = defaultGROReadBufferSize
		}
		buffers[i] = make([]byte, size)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{
			{Base: &buffers[i][0], Len: uint32(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint32(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))

		if controlLen > 0 {
			controls[i] = make([]byte, controlLen)
			msgs[i].Hdr.Control = &controls[i][0]
			msgs[i].Hdr.Controllen = controllen(len(controls[i]))
		} else {
			msgs[i].Hdr.Control = nil
			msgs[i].Hdr.Controllen = controllen(0)
		}
	}

	return msgs, buffers, names, controls
}
