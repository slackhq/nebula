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

type EncBatchReader func(
	addrs []netip.AddrPort,
	payloads [][]byte,
	count int,
)

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	ListenOut(r EncReader)
	ListenOutBatch(r EncBatchReader)
	WriteTo(b []byte, addr netip.AddrPort) error
	WriteMulti(packets [][]byte, addrs []netip.AddrPort) (int, error)
	ReloadConfig(c *config.C)
	BatchSize() int
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
func (NoopConn) ListenOutBatch(_ EncBatchReader) {
	return
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) WriteMulti(_ [][]byte, _ []netip.AddrPort) (int, error) {
	return 0, nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) BatchSize() int {
	return 1
}
func (NoopConn) Close() error {
	return nil
}
