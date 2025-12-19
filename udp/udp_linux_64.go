//go:build linux && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || s390x || riscv64 || loong64) && !android && !e2e_testing
// +build linux
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le s390x riscv64 loong64
// +build !android
// +build !e2e_testing

package udp

import (
	"github.com/slackhq/nebula/packet"
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

func setRawMessageControl(msg *rawMessage, buf []byte) {
	if len(buf) == 0 {
		msg.Hdr.Control = nil
		msg.Hdr.Controllen = 0
		return
	}
	msg.Hdr.Control = &buf[0]
	msg.Hdr.Controllen = uint64(len(buf))
}

func getRawMessageControlLen(msg *rawMessage) int {
	return int(msg.Hdr.Controllen)
}

func setCmsgLen(h *unix.Cmsghdr, l int) {
	h.Len = uint64(l)
}

func (u *StdConn) PrepareRawMessages(n int, isV4 bool) ([]rawMessage, []*packet.UDPPacket) {
	msgs := make([]rawMessage, n)
	packets := make([]*packet.UDPPacket, n)

	for i := range msgs {
		packets[i] = packet.New(isV4)

		vs := []iovec{
			{Base: &packets[i].Payload[0], Len: uint64(packet.Size)},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = &packets[i].Name[0]
		msgs[i].Hdr.Namelen = uint32(len(packets[i].Name))

		if u.enableGRO {
			msgs[i].Hdr.Control = &packets[i].Control[0]
			msgs[i].Hdr.Controllen = uint64(len(packets[i].Control))
		} else {
			msgs[i].Hdr.Control = nil
			msgs[i].Hdr.Controllen = 0
		}
	}

	return msgs, packets
}

func setIovecSlice(iov *iovec, b []byte) {
	if len(b) == 0 {
		iov.Base = nil
		iov.Len = 0
		return
	}
	iov.Base = &b[0]
	iov.Len = uint64(len(b))
}
