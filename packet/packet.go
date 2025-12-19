package packet

import (
	"encoding/binary"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const Size = 0xffff

type UDPPacket struct {
	Payload []byte
	Control []byte
	Name    []byte
	SegSize int

	ReadyToSend  bool
	wasSegmented bool
	isV4         bool
}

func New(isV4 bool) *UDPPacket {
	return &UDPPacket{
		Payload: make([]byte, Size),
		Control: make([]byte, unix.CmsgSpace(2)),
		Name:    make([]byte, unix.SizeofSockaddrInet6),
		isV4:    isV4,
	}
}

func (p *UDPPacket) AddrPort() netip.AddrPort {
	var ip netip.Addr
	// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
	if p.isV4 {
		ip, _ = netip.AddrFromSlice(p.Name[4:8])
	} else {
		ip, _ = netip.AddrFromSlice(p.Name[8:24])
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(p.Name[2:4]))
}

func (p *UDPPacket) encodeSockaddr(dst []byte, addr netip.AddrPort) (uint32, error) {
	//todo no chance this works on windows?
	if p.isV4 {
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

func (p *UDPPacket) SetAddrPort(addr netip.AddrPort) error {
	nl, err := p.encodeSockaddr(p.Name, addr)
	if err != nil {
		return err
	}
	p.Name = p.Name[:nl]
	return nil
}

func (p *UDPPacket) updateCtrl(ctrlLen int) {
	p.SegSize = len(p.Payload)
	p.wasSegmented = false
	if ctrlLen == 0 {
		return
	}
	if len(p.Control) == 0 {
		return
	}
	header, data, _ /*remain*/, err := unix.ParseOneSocketControlMessage(p.Control)
	if err != nil {
		return // oh well
	}

	if header.Level == unix.SOL_UDP && header.Type == unix.UDP_GRO && len(data) >= 2 {
		p.wasSegmented = true
		p.SegSize = int(binary.LittleEndian.Uint16(data[:2]))
		return
	}
}

// Update sets a UDPPacket into "just received, not processed" state
func (p *UDPPacket) Update(ctrlLen int) {
	p.updateCtrl(ctrlLen)
}

func (p *UDPPacket) SetSegSizeForTX() {
	p.SegSize = len(p.Payload)
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&p.Control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(syscall.CmsgLen(2))
	binary.NativeEndian.PutUint16(p.Control[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(p.SegSize))
}

func (p *UDPPacket) CompatibleForSegmentationWith(otherP *UDPPacket, currentTotalSize int) bool {
	//same dest
	if !slices.Equal(p.Name, otherP.Name) {
		return false
	}

	//don't get too big
	if len(p.Payload)+currentTotalSize >= 0xffff {
		return false
	}

	//same body len
	//todo allow single different size at end
	if len(p.Payload) != len(otherP.Payload) {
		return false //todo technically you can cram one extra in
	}
	return true
}

func (p *UDPPacket) Segments() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		//cursor := 0
		for offset := 0; offset < len(p.Payload); offset += p.SegSize {
			end := offset + p.SegSize
			if end > len(p.Payload) {
				end = len(p.Payload)
			}
			if !yield(p.Payload[offset:end]) {
				return
			}
		}
	}
}
