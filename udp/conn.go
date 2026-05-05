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
	ListenOut(r EncReader) error
	WriteTo(b []byte, addr netip.AddrPort) error
	ReloadConfig(c *config.C)
	SupportsMultipleReaders() bool
	// EnablePathMTUDiscovery sets the don't-fragment bit on outgoing packets for
	// this socket. Called by the pmtud manager when PMTUD is enabled. A no-op on
	// platforms that don't support it; nebula's default behavior (no DF, kernel
	// fragmentation allowed) is preserved on those platforms and on this one when
	// PMTUD is disabled.
	EnablePathMTUDiscovery() error
	Close() error
}

type NoopConn struct{}

func (NoopConn) Rebind() error {
	return nil
}
func (NoopConn) LocalAddr() (netip.AddrPort, error) {
	return netip.AddrPort{}, nil
}
func (NoopConn) ListenOut(_ EncReader) error {
	return nil
}
func (NoopConn) SupportsMultipleReaders() bool {
	return false
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) EnablePathMTUDiscovery() error {
	return nil
}
func (NoopConn) Close() error {
	return nil
}
