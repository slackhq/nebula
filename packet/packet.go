package packet

import (
	"encoding/binary"
	"iter"
	"net/netip"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const Size = 0xffff

type Packet struct {
	Payload []byte
	Control []byte
	Name    []byte
	SegSize int

	//todo should this hold out as well?
	OutLen int

	wasSegmented bool
	isV4         bool
}

func New(isV4 bool) *Packet {
	return &Packet{
		Payload: make([]byte, Size),
		Control: make([]byte, unix.CmsgSpace(2)),
		Name:    make([]byte, unix.SizeofSockaddrInet6),
		isV4:    isV4,
	}
}

func (p *Packet) AddrPort() netip.AddrPort {
	var ip netip.Addr
	// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
	if p.isV4 {
		ip, _ = netip.AddrFromSlice(p.Name[4:8])
	} else {
		ip, _ = netip.AddrFromSlice(p.Name[8:24])
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(p.Name[2:4]))
}

func (p *Packet) updateCtrl(ctrlLen int) {
	p.SegSize = len(p.Payload)
	p.wasSegmented = false
	if ctrlLen == 0 {
		return
	}
	if len(p.Control) == 0 {
		return
	}
	cmsgs, err := unix.ParseSocketControlMessage(p.Control)
	if err != nil {
		return // oh well
	}

	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 2 {
			p.wasSegmented = true
			p.SegSize = int(binary.LittleEndian.Uint16(c.Data[:2]))
			return
		}
	}
}

// Update sets a Packet into "just received, not processed" state
func (p *Packet) Update(ctrlLen int) {
	p.OutLen = -1
	p.updateCtrl(ctrlLen)
}

func (p *Packet) SetSegSizeForTX() {
	p.SegSize = len(p.Payload)
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&p.Control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(syscall.CmsgLen(2))
	binary.NativeEndian.PutUint16(p.Control[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(p.SegSize))
}

func (p *Packet) CompatibleForSegmentationWith(otherP *Packet, currentTotalSize int) bool {
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

func (p *Packet) Segments() iter.Seq[[]byte] {
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
