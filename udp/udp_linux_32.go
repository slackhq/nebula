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
			{Base: &buffers[i][0], Len: uint32(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint32(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))

		// Set up control message buffer for GRO
		if controlSize > 0 {
			controls[i] = make([]byte, controlSize)
			msgs[i].Hdr.Control = &controls[i][0]
			msgs[i].Hdr.Controllen = uint32(controlSize)
		}
	}

	return msgs, buffers, names, controls
}

func setIovecBase(iov *iovec, base *byte) {
	iov.Base = base
}

func setIovecLen(iov *iovec, l int) {
	iov.Len = uint32(l)
}

func setMsghdrIovlen(hdr *msghdr, l int) {
	hdr.Iovlen = uint32(l)
}

func setMsghdrControllen(hdr *msghdr, l int) {
	hdr.Controllen = uint32(l)
}

func getMsghdrControllen(hdr *msghdr) int {
	return int(hdr.Controllen)
}
