package udp

import (
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

const MTU = 9001

type EncReader func(
	addr *Addr,
	out []byte,
	packet []byte,
	header *header.H,
	fwPacket *firewall.Packet,
	lhh LightHouseHandlerFunc,
	nb []byte,
	q int,
	localCache firewall.ConntrackCache,
)

type Conn interface {
	Rebind() error
	LocalAddr() (*Addr, error)
	ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int)
	WriteTo(b []byte, addr *Addr) error
	ReloadConfig(c *config.C)
	Close() error
}

type NoopConn struct{}

func (NoopConn) Rebind() error {
	return nil
}
func (NoopConn) LocalAddr() (*Addr, error) {
	return nil, nil
}
func (NoopConn) ListenOut(_ EncReader, _ LightHouseHandlerFunc, _ *firewall.ConntrackCacheTicker, _ int) {
	return
}
func (NoopConn) WriteTo(_ []byte, _ *Addr) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}
