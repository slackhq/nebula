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

func (u *StdConn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, [][]byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)

	for i := range msgs {
		buffers[i] = make([]byte, MTU)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{
			{Base: &buffers[i][0], Len: uint32(len(buffers[i]))},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint32(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, buffers, names
}

// prepareWriteMessages allocates one Mmsghdr/iovec/sockaddr scratch per slot,
// wired up so each writeMsgs[i] already points at writeIovs[i] and
// writeNames[i]. Callers fill in the iovec Base/Len, the sockaddr bytes, and
// Namelen before each sendmmsg.
func (u *StdConn) prepareWriteMessages(n int) {
	u.writeMsgs = make([]rawMessage, n)
	u.writeIovs = make([]iovec, n)
	u.writeNames = make([][]byte, n)
	for i := range u.writeMsgs {
		u.writeNames[i] = make([]byte, unix.SizeofSockaddrInet6)
		u.writeMsgs[i].Hdr.Iov = &u.writeIovs[i]
		u.writeMsgs[i].Hdr.Iovlen = 1
		u.writeMsgs[i].Hdr.Name = &u.writeNames[i][0]
	}
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
