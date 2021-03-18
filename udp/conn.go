package udp

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
	SetRecvBuffer(n int) error
	SetSendBuffer(n int) error
	GetRecvBuffer() (int, error)
	GetSendBuffer() (int, error)
	LocalAddr() (*Addr, error)
	ListenOut(reader EncReader, lhh LightHouseHandlerFunc, cache *ConntrackCacheTicker, q int) error
	WriteTo(b []byte, addr *Addr) error
	//TODO: last stragler, needs an interface
	//ReloadConfig(c *nebula.Config)
	EmitStats() error
}
