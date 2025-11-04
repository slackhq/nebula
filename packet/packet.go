package packet

import (
	"net/netip"
	"sync"
)

const Size = 9001

type Packet struct {
	Payload []byte
	Addr    netip.AddrPort
}

func New() *Packet {
	return &Packet{Payload: make([]byte, Size)}
}

type Pool struct {
	pool sync.Pool
}

func NewPool() *Pool {
	return &Pool{
		pool: sync.Pool{New: func() any { return New() }},
	}
}

func (p *Pool) Get() *Packet {
	return p.pool.Get().(*Packet)
}

func (p *Pool) Put(x *Packet) {
	x.Payload = x.Payload[:Size]
	p.pool.Put(x)
}
