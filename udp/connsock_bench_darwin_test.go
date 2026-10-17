//go:build !e2e_testing

package udp

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// benchConnSocks opens a wildcard listener with ListenOut running, with the connected socket knobs pinned to
// their defaults and then cfg applied, and a loopback peer that never reads, so its sends cost only the sender.
func benchConnSocks(b *testing.B, s Settings, cfg func(*connSockConfig)) (*StdConn, netip.AddrPort) {
	b.Helper()
	for k, v := range map[string]string{
		"NEBULA_CONNSOCKS":           "8",
		"NEBULA_CONNSOCK_RUN":        "64",
		"NEBULA_CONNSOCK_WINDOW":     "1s",
		"NEBULA_CONNSOCK_IDLE":       "30s",
		"NEBULA_CONNSOCK_OPEN_EVERY": "1s",
	} {
		b.Setenv(k, v)
	}
	c, err := NewListener(slog.New(slog.DiscardHandler), s)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	u := c.(*StdConn)
	if cfg != nil {
		cfg(&u.socks.cfg)
	}
	go func() { _ = u.ListenOut(func(netip.AddrPort, []byte) {}, func() {}) }()
	for u.reader.Load() == nil {
		time.Sleep(time.Millisecond)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = pc.Close() })
	return u, pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// BenchmarkConnSockWriteTo measures one WriteTo of a full-size datagram down each path: the listener with
// connected sockets off, to a destination that is no tunnel's remote while another is, to an established peer
// that never gets busy, and on a connected socket.
func BenchmarkConnSockWriteTo(b *testing.B) {
	pkt := make([]byte, 1400)
	cases := []struct {
		name  string
		cfg   func(*connSockConfig)
		setup func(b *testing.B, u *StdConn, dst netip.AddrPort)
	}{
		{name: "listener/off", cfg: func(c *connSockConfig) { c.max = 0 }},
		{name: "listener/ineligible", setup: func(b *testing.B, u *StdConn, dst netip.AddrPort) {
			u.SetEstablishedPeer(netip.AddrPortFrom(dst.Addr(), dst.Port()+1), true)
		}},
		{name: "listener/eligible-not-busy", cfg: func(c *connSockConfig) { c.run = 1 << 30 },
			setup: func(b *testing.B, u *StdConn, dst netip.AddrPort) { u.SetEstablishedPeer(dst, true) }},
		{name: "connected", setup: func(b *testing.B, u *StdConn, dst netip.AddrPort) {
			u.SetEstablishedPeer(dst, true)
			for range u.socks.cfg.run {
				_ = u.WriteTo(pkt, dst)
			}
			if u.connSockFor(dst) == nil {
				b.Fatal("no connected socket")
			}
		}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			u, dst := benchConnSocks(b, Settings{Listen: netip.MustParseAddrPort("0.0.0.0:0")}, c.cfg)
			if c.setup != nil {
				c.setup(b, u, dst)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = u.WriteTo(pkt, dst)
			}
		})
	}
}

// BenchmarkConnSockDispatch measures what WriteTo adds before the listener's sendto, without the syscall: a v4
// listener refuses a v6 destination before sending, with connected sockets off or with another peer established.
func BenchmarkConnSockDispatch(b *testing.B) {
	pkt := make([]byte, 1400)
	dst := netip.MustParseAddrPort("[::1]:4242")
	for _, c := range []struct {
		name      string
		cfg       func(*connSockConfig)
		establish bool
	}{
		{name: "off", cfg: func(c *connSockConfig) { c.max = 0 }},
		{name: "ineligible", establish: true},
	} {
		b.Run(c.name, func(b *testing.B) {
			u, peer := benchConnSocks(b, Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Multi: true}, c.cfg)
			if c.establish {
				u.SetEstablishedPeer(peer, true)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if u.WriteTo(pkt, dst) == nil {
					b.Fatal("sent a v6 datagram on a v4 listener")
				}
			}
		})
	}
}
