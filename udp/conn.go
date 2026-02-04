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

// BatchPacket represents a single packet in a batch write operation
type BatchPacket struct {
	Payload []byte
	Addr    netip.AddrPort
}

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	ListenOut(r EncReader)
	WriteTo(b []byte, addr netip.AddrPort) error
	WriteBatch(pkts []BatchPacket) (int, error)
	ReloadConfig(c *config.C)
	SupportsMultipleReaders() bool
	SupportsGSO() bool
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
func (NoopConn) SupportsMultipleReaders() bool {
	return false
}
func (NoopConn) SupportsGSO() bool {
	return false
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) WriteBatch(pkts []BatchPacket) (int, error) {
	return len(pkts), nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}
