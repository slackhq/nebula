package udp

import (
	"net/netip"

	"github.com/slackhq/nebula/config"
)

const MTU = 9001

// MaxWriteBatch is the largest batch any Conn.WriteBatch implementation is
// required to accept. Callers SHOULD NOT pass more than this per call; Linux
// backends preallocate sendmmsg scratch sized to this value, so exceeding it
// only costs a chunked retry.
const MaxWriteBatch = 128

type EncReader func(
	addr netip.AddrPort,
	payload []byte,
)

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	// ListenOut invokes r for each received packet. On batch-capable
	// backends (recvmmsg), flush is called after each batch is fully
	// delivered — callers use it to flush per-batch accumulators such as
	// TUN write coalescers. Single-packet backends call flush after each
	// packet. flush must not be nil.
	ListenOut(r EncReader, flush func()) error
	WriteTo(b []byte, addr netip.AddrPort) error
	// WriteBatch sends a contiguous batch of packets, each with its own
	// destination. bufs and addrs must have the same length. Linux uses
	// sendmmsg(2) for a single syscall; other backends fall back to a
	// WriteTo loop. Returns on the first error; callers may observe a
	// partial send if some packets went out before the error.
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) error
	ReloadConfig(c *config.C)
	SupportsMultipleReaders() bool
	Close() error
}

type NoopConn struct{}

func (NoopConn) Rebind() error {
	return nil
}
func (NoopConn) LocalAddr() (netip.AddrPort, error) {
	return netip.AddrPort{}, nil
}
func (NoopConn) ListenOut(_ EncReader, _ func()) error {
	return nil
}
func (NoopConn) SupportsMultipleReaders() bool {
	return false
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) WriteBatch(_ [][]byte, _ []netip.AddrPort) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}
