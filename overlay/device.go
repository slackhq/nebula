package overlay

import (
	"io"
	"net/netip"
	"sync"

	"github.com/slackhq/nebula/routing"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}

// Packet represents a single packet buffer with optional headroom to carry
// metadata (for example virtio-net headers).
type Packet struct {
	Buf     []byte
	Offset  int
	Len     int
	release func()
}

func (p *Packet) Payload() []byte {
	return p.Buf[p.Offset : p.Offset+p.Len]
}

func (p *Packet) Reset() {
	p.Len = 0
	p.Offset = 0
	p.release = nil
}

func (p *Packet) Release() {
	if p.release != nil {
		p.release()
		p.release = nil
	}
}

func (p *Packet) Capacity() int {
	return len(p.Buf) - p.Offset
}

// PacketPool manages reusable buffers with headroom.
type PacketPool struct {
	headroom int
	blksz    int
	pool     sync.Pool
}

func NewPacketPool(headroom, payload int) *PacketPool {
	p := &PacketPool{headroom: headroom, blksz: headroom + payload}
	p.pool.New = func() any {
		buf := make([]byte, p.blksz)
		return &Packet{Buf: buf, Offset: headroom}
	}
	return p
}

func (p *PacketPool) Get() *Packet {
	pkt := p.pool.Get().(*Packet)
	pkt.Offset = p.headroom
	pkt.Len = 0
	pkt.release = func() { p.put(pkt) }
	return pkt
}

func (p *PacketPool) put(pkt *Packet) {
	pkt.Reset()
	p.pool.Put(pkt)
}

// BatchReader allows reading multiple packets into a shared pool with
// preallocated headroom (e.g. virtio-net headers).
type BatchReader interface {
	ReadIntoBatch(pool *PacketPool) ([]*Packet, error)
}

// BatchWriter writes a slice of packets that carry their own metadata.
type BatchWriter interface {
	WriteBatch(packets []*Packet) (int, error)
}

// BatchCapableDevice describes a device that can efficiently read and write
// batches of packets with virtio headroom.
type BatchCapableDevice interface {
	Device
	BatchReader
	BatchWriter
	BatchHeadroom() int
	BatchPayloadCap() int
	BatchSize() int
}
