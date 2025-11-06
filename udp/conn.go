package udp

import (
	"net/netip"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/packet"
)

const MTU = 9001

type EncReader func(*packet.Packet)

type PacketBufferGetter func() *packet.Packet

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	ListenOut(pg PacketBufferGetter, pc chan *packet.Packet) error
	WriteTo(p *packet.Packet) error
	WriteDirect(b []byte, port netip.AddrPort) error
	ReloadConfig(c *config.C)
	Close() error
}

type NoopConn struct{}

func (NoopConn) Rebind() error {
	return nil
}
func (NoopConn) LocalAddr() (netip.AddrPort, error) {
	return netip.AddrPort{}, nil
}
func (NoopConn) ListenOut(_ EncReader) {
	return
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}
