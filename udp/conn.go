package udp

import c "github.com/slackhq/nebula/config"

type EncReader func(
	addr *Addr,
	out []byte,
	packet []byte,
	header *Header,
	fwPacket *FirewallPacket,
	lhh LightHouseHandlerFunc,
	nb []byte,
	q int,
	localCache ConntrackCache,
)

type Conn interface {
	Rebind() error
	LocalAddr() (*Addr, error)
	ListenOut(reader EncReader, lhh LightHouseHandlerFunc, cache *ConntrackCacheTicker, q int) error
	WriteTo(b []byte, addr *Addr) error
	//TODO: an interface is going to be a lot cleaner than this
	ReloadConfig(config *c.Config)
	EmitStats() error
}
