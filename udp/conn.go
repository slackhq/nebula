package udp

import "github.com/slackhq/nebula"

type EncReader func(
	addr *Addr,
	out []byte,
	packet []byte,
	header *nebula.Header,
	fwPacket *firewall.FirewallPacket,
	lhh *nebula.LightHouseHandler,
	nb []byte,
	q int,
	localCache nebula.ConntrackCache,
)

type Conn interface {
	Rebind() error
	SetRecvBuffer() error
	SetSendBuffer() error
	GetRecvBuffer() (int, error)
	GetSendBuffer() (int, error)
	LocalAddr() (*Addr, error)
	ListenOut(reader EncReader, lhh *nebula.LightHouseHandler, cache *nebula.ConntrackCacheTicker, q int) error
	WriteTo(b []byte, addr *Addr) error
	ReloadConfig(c *nebula.Config)
	EmitStats() error
}
