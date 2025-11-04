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

func (u *StdConn) PrepareRawMessages(n int, pg PacketBufferGetter) ([]rawMessage, []*packet.Packet, [][]byte) {
	msgs := make([]rawMessage, n)
	names := make([][]byte, n)

	packets := make([]*packet.Packet, n)
	for i := range packets {
		packets[i] = pg()
	}

	for i := range msgs {
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		vs := []iovec{
			{Base: &packets[i].Payload[0], Len: uint64(packet.Size)},
		}

		msgs[i].Hdr.Iov = &vs[0]
		msgs[i].Hdr.Iovlen = uint64(len(vs))

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))
	}

	return msgs, packets, names
}
