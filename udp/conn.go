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

// RxMeta carries per-packet metadata extracted from the RX path (ancillary
// data, kernel offload state, etc.) and passed to EncReader callbacks.
// Backends that do not produce a particular signal leave its zero value.
//
// OuterECN is the 2-bit IP-level ECN codepoint stamped on the carrier
// datagram (extracted from IP_TOS / IPV6_TCLASS cmsg on Linux). Zero
// means Not-ECT (Not ECN-Capable Transport, per RFC 3168) — i.e. the
// sender is not participating in ECN — which is also the value backends
// without ECN RX support supply on every packet.
type RxMeta struct {
	OuterECN byte
}

type EncReader func(
	addr netip.AddrPort,
	payload []byte,
	meta RxMeta,
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
	// destination. bufs and addrs must have the same length. outerECNs may
	// be nil (treated as all-zero / Not-ECT, i.e. Not ECN-Capable Transport);
	// when non-nil it must have the
	// same length as bufs, and outerECNs[i] is the 2-bit IP-level ECN
	// codepoint to set on packet i's outer header. Linux uses sendmmsg(2)
	// for a single syscall and attaches the value as IP_TOS / IPV6_TCLASS
	// cmsg; other backends ignore it. Returns on the first error; callers
	// may observe a partial send if some packets went out before the error.
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort, outerECNs []byte) error
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
func (NoopConn) WriteBatch(_ [][]byte, _ []netip.AddrPort, _ []byte) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
}
func (NoopConn) Close() error {
	return nil
}
