package udp

import (
	"net/netip"

	"github.com/slackhq/nebula/config"
)

const MTU = 9001

type EncReader func(
	addr netip.AddrPort,
	payload []byte,
)

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	ListenOut(r EncReader)
	WriteTo(b []byte, addr netip.AddrPort) error
	ReloadConfig(c *config.C)
	Close() error
}

// Datagram represents a UDP payload destined to a specific address.
type Datagram struct {
	Payload []byte
	Addr    netip.AddrPort
}

// BatchConn can send multiple datagrams in one syscall.
type BatchConn interface {
	Conn
	WriteBatch(pkts []Datagram) error
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
