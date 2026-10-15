package udp

import (
	"net/netip"

	"github.com/slackhq/nebula/config"
)

const MTU = 9001

// MaxWriteBatch is the largest batch any Conn.WriteBatch implementation is
// required to accept. Callers SHOULD NOT pass more than this per call; Linux
// backends preallocate sendmmsg scratch sized to this value, so exceeding it
// only costs additional sendmmsg chunks within a single WriteBatch call.
const MaxWriteBatch = 128

type EncReader func(
	addr netip.AddrPort,
	payload []byte,
)

type Settings struct {
	Listen   netip.AddrPort
	Multi    bool
	Batch    int
	Offloads bool
}

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	// ListenOut invokes r for each received packet. The packets alias the receive buffers.
	// After each batch is fully delivered (after each packet on single-packet backends), handoff takes the batch's
	// buffers and returns the ones to receive the next batch into: the same ones once the caller is done with the
	// packets, after flushing per-batch accumulators such as TUN write coalescers, or replacements of the same count
	// and size to keep them. handoff must not be nil.
	ListenOut(r EncReader, handoff func(bufs [][]byte) [][]byte) error
	WriteTo(b []byte, addr netip.AddrPort) error
	// WriteBatch sends a contiguous batch of packets, each with its own
	// destination. bufs and addrs must have the same length. Linux uses
	// sendmmsg(2) for a single syscall.
	//
	// Returns the number of packets successfully written. A destination the kernel rejects costs only
	// its own packet, so a short count means some peers were undeliverable, not that the batch failed.
	// Not safe for concurrent use on the same Conn.
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error)
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
func (NoopConn) ListenOut(_ EncReader, _ func([][]byte) [][]byte) error {
	return nil
}
func (NoopConn) SupportsMultipleReaders() bool {
	return false
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	return len(bufs), nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}
