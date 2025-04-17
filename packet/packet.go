package packet

import "net/netip"

type Packet struct {
	Payload []byte
	Addr    netip.AddrPort
}

func New() *Packet {
	return &Packet{Payload: make([]byte, 9001)}
}
