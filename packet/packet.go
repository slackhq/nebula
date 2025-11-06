package packet

import (
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

const Size = 0xffff

type Packet struct {
	Payload []byte
	Control []byte
	SegSize int
	Addr    netip.AddrPort
}

func New() *Packet {
	return &Packet{
		Payload: make([]byte, Size),
		Control: make([]byte, unix.CmsgSpace(2)),
	}
}

type Pool struct {
	pool sync.Pool
}

var bigPool = &Pool{
	pool: sync.Pool{New: func() any { return New() }},
}

func GetPool() *Pool {
	return bigPool
}

func (p *Pool) Get() *Packet {
	return p.pool.Get().(*Packet)
}

func (p *Pool) Put(x *Packet) {
	x.Payload = x.Payload[:Size]
	p.pool.Put(x)
}
