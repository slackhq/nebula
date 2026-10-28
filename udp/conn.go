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
	// CanSendIPv4 reports whether this conn's socket can send to IPv4 remotes
	CanSendIPv4() bool
	// CanSendIPv6 reports whether this conn's socket can send to IPv6 remotes
	CanSendIPv6() bool
	// ListenOut invokes r for each received packet.
	// On batch-capable backends (recvmmsg), flush is called after each batch is fully delivered.
	// Callers use it to flush per-batch accumulators such as TUN write coalescers.
	// Single-packet backends call flush after each packet. flush must not be nil.
	ListenOut(r EncReader, flush func()) error
	WriteTo(b []byte, addr netip.AddrPort) error
	// WriteBatch sends a contiguous batch of packets, each with its own
	// destination. bufs and addrs must have the same length. Linux uses
	// sendmmsg(2) for a single syscall.
	//
	// Returns the number of packets successfully written. A destination the kernel rejects costs only
	// its own packet, so a short count means some peers were undeliverable, not that the batch failed.
	// Safe for concurrent use on the same Conn.
	WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error)
	// ReloadConfig applies the listen settings that can change, r is nil at startup
	ReloadConfig(c *config.C, r *config.Reload)
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
func (NoopConn) CanSendIPv4() bool {
	return true
}
func (NoopConn) CanSendIPv6() bool {
	return true
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
func (NoopConn) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	return len(bufs), nil
}
func (NoopConn) ReloadConfig(_ *config.C, _ *config.Reload) {
	return
}
func (NoopConn) Close() error {
	return nil
}

// families records which address families a socket can send to, conns embed it for CanSendIPv4 and CanSendIPv6
type families struct {
	v4, v6 bool
}

func (f families) CanSendIPv4() bool {
	return f.v4
}

func (f families) CanSendIPv6() bool {
	return f.v6
}

// socketFamilies returns the families the socket fd, bound to local, can send to. An IPv6 socket reaches IPv4 too only
// when it is bound to the wildcard with IPV6_V6ONLY cleared, which is read from the socket rather than assumed, a socket
// bound to a specific IPv6 address never does.
func socketFamilies(local netip.Addr, fd uintptr) (families, error) {
	if local.Is4() {
		return families{v4: true}, nil
	}
	if !local.IsUnspecified() {
		return families{v6: true}, nil
	}

	v6only, err := getV6Only(fd)
	if err != nil {
		return families{}, err
	}
	return families{v4: !v6only, v6: true}, nil
}
