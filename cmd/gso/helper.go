package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

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

type BatchPacket struct {
	Payload []byte
	Addr    netip.AddrPort
}

func encodeSockaddr(dst []byte, addr netip.AddrPort) (uint32, error) {
	if addr.Addr().Is4() {
		if !addr.Addr().Is4() {
			return 0, fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
		}
		var sa unix.RawSockaddrInet4
		sa.Family = unix.AF_INET
		sa.Addr = addr.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
		size := unix.SizeofSockaddrInet4
		copy(dst[:size], (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:])
		return uint32(size), nil
	}

	var sa unix.RawSockaddrInet6
	sa.Family = unix.AF_INET6
	sa.Addr = addr.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], addr.Port())
	size := unix.SizeofSockaddrInet6
	copy(dst[:size], (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:])
	return uint32(size), nil
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

func setCmsgLen(h *unix.Cmsghdr, l int) {
	h.Len = uint64(l)
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
