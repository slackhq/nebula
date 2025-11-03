//go:build linux && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || s390x || riscv64 || loong64) && !android && !e2e_testing
// +build linux
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le s390x riscv64 loong64
// +build !android
// +build !e2e_testing

package udp

import (
	"errors"
	"fmt"

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
	controlLen := int(u.controlLen.Load())

	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	var controls [][]byte
	if controlLen > 0 {
		controls = make([][]byte, n)
	}

	for i := range msgs {
		size := int(u.groBufSize.Load())
		if size < MTU {
			size = MTU
		}
		buf := u.borrowRxBuffer(size)
		buffers[i] = buf
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{{Base: &buf[0], Len: uint64(len(buf))}}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

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

func setIovecBase(msg *rawMessage, buf []byte) {
	iov := (*iovec)(msg.Hdr.Iov)
	iov.Base = &buf[0]
	iov.Len = uint64(len(buf))
}

func rawMessageToUnixMsghdr(msg *rawMessage) (unix.Msghdr, unix.Iovec, error) {
	var hdr unix.Msghdr
	var iov unix.Iovec
	if msg == nil {
		return hdr, iov, errors.New("nil rawMessage")
	}
	if msg.Hdr.Iov == nil || msg.Hdr.Iov.Base == nil {
		return hdr, iov, errors.New("rawMessage missing payload buffer")
	}
	payloadLen := int(msg.Hdr.Iov.Len)
	if payloadLen < 0 {
		return hdr, iov, fmt.Errorf("invalid payload length: %d", payloadLen)
	}
	iov.Base = msg.Hdr.Iov.Base
	iov.Len = uint64(payloadLen)
	hdr.Iov = &iov
	hdr.Iovlen = 1
	hdr.Name = msg.Hdr.Name
	// CRITICAL: Always set to full buffer size for receive, not what kernel wrote last time
	if hdr.Name != nil {
		hdr.Namelen = uint32(unix.SizeofSockaddrInet6)
	} else {
		hdr.Namelen = 0
	}
	hdr.Control = msg.Hdr.Control
	// CRITICAL: Use the allocated size, not what was previously returned
	if hdr.Control != nil {
		// Control buffer size is stored in Controllen from PrepareRawMessages
		hdr.Controllen = msg.Hdr.Controllen
	} else {
		hdr.Controllen = 0
	}
	hdr.Flags = 0 // Reset flags for new receive
	return hdr, iov, nil
}

func updateRawMessageFromUnixMsghdr(msg *rawMessage, hdr *unix.Msghdr, n int) {
	if msg == nil || hdr == nil {
		return
	}
	msg.Hdr.Namelen = hdr.Namelen
	msg.Hdr.Controllen = hdr.Controllen
	msg.Hdr.Flags = hdr.Flags
	if n < 0 {
		n = 0
	}
	msg.Len = uint32(n)
}
