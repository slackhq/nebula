//go:build !e2e_testing

package udp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newConnSockListener opens a listener with the connected socket knobs pinned to their defaults, so NEBULA_*
// variables in the environment can't change what a test sees, applies cfg, and starts ListenOut with r.
func newConnSockListener(t *testing.T, s Settings, h slog.Handler, r EncReader, cfg ...func(*connSockConfig)) *StdConn {
	t.Helper()
	for k, v := range map[string]string{
		"NEBULA_CONNSOCKS":           "8",
		"NEBULA_CONNSOCK_RUN":        "64",
		"NEBULA_CONNSOCK_WINDOW":     "1s",
		"NEBULA_CONNSOCK_IDLE":       "30s",
		"NEBULA_CONNSOCK_OPEN_EVERY": "1s",
	} {
		t.Setenv(k, v)
	}
	if h == nil {
		h = slog.DiscardHandler
	}
	if r == nil {
		r = func(netip.AddrPort, []byte) {}
	}
	c, err := NewListener(slog.New(h), s)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	u := c.(*StdConn)
	for _, f := range cfg {
		f(&u.socks.cfg)
	}
	go func() { _ = u.ListenOut(r, func() {}) }()
	require.Eventually(t, func() bool { return u.reader.Load() != nil }, 5*time.Second, time.Millisecond)
	return u
}

func listen(s string) Settings { return Settings{Listen: netip.MustParseAddrPort(s)} }

// run builds n datagrams to dst.
func run(dst netip.AddrPort, n int, tag string) ([][]byte, []netip.AddrPort) {
	bufs := make([][]byte, n)
	addrs := make([]netip.AddrPort, n)
	for i := range bufs {
		bufs[i] = fmt.Appendf(nil, "%s-%d", tag, i)
		addrs[i] = dst
	}
	return bufs, addrs
}

func newPeer(t *testing.T, network, addr string) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	return uc, uc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// newEstablishedPeer opens a peer as newPeer does and tells u it is an established tunnel's remote.
func newEstablishedPeer(t *testing.T, u *StdConn, network, addr string) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	c, dst := newPeer(t, network, addr)
	u.SetEstablishedPeer(dst, true)
	return c, dst
}

// readFrom reads n datagrams at peer and returns the source of each.
func readFrom(t *testing.T, peer *net.UDPConn, n int) []netip.AddrPort {
	t.Helper()
	buf := make([]byte, MTU)
	var from []netip.AddrPort
	for range n {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, f, err := peer.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		from = append(from, netip.AddrPortFrom(f.Addr().Unmap(), f.Port()))
	}
	return from
}

func reusePort(t *testing.T, c syscall.Conn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var v int
	var serr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		v, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
	}))
	require.NoError(t, serr)
	return v
}

// rogueBinds tries each of binds, "network address plain|reuseport", on port and returns the ones that bound.
func rogueBinds(t *testing.T, port uint16, binds []string) []string {
	t.Helper()
	var bound []string
	for _, b := range binds {
		f := strings.Fields(b)
		network, addr, reuse := f[0], f[1], f[2]
		lc := net.ListenConfig{Control: connSockControl(reuse == "reuseport", 0)}
		pc, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort(addr, fmt.Sprint(port)))
		if err == nil {
			_ = pc.Close()
			bound = append(bound, b)
		}
	}
	return bound
}

// The listener never sets SO_REUSEPORT, and a connected socket binds with it only to a specific address, so every
// bind a lone listener refuses is refused after NewListener returns and while connected sockets are open. Same-uid
// SO_REUSEPORT binds to a specific address are left out: xnu allows them beside a lone wildcard listener too,
// which is how a connected socket binds, and refuses them to any other uid.
func TestConnSocksNoSharedBind(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	la, err := u.LocalAddr()
	require.NoError(t, err)
	binds := []string{
		"udp4 0.0.0.0 plain", "udp4 0.0.0.0 reuseport", "udp4 127.0.0.1 plain",
		"udp6 :: plain", "udp6 :: reuseport", "udp6 ::1 plain",
	}
	assert.Zero(t, reusePort(t, u.UDPConn), "listener")
	assert.Empty(t, rogueBinds(t, la.Port(), binds), "bound beside the listener")

	peer4, dst4 := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	peer6, dst6 := newEstablishedPeer(t, u, "udp6", "[::1]:0")
	for _, p := range []struct {
		c   *net.UDPConn
		dst netip.AddrPort
	}{{peer4, dst4}, {peer6, dst6}} {
		bufs, addrs := run(p.dst, u.socks.cfg.run, "p")
		_, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		readFrom(t, p.c, len(bufs))
		s := u.connSockFor(p.dst)
		require.NotNil(t, s, "no connected socket to %v", p.dst)
		assert.NotZero(t, reusePort(t, s.conn), "connected socket to %v", p.dst)
	}
	assert.Empty(t, rogueBinds(t, la.Port(), binds), "bound beside the connected sockets")
}

// A connected socket binds the source address the listener's route to its peer picks, for either family on a
// dual-stack listener, so the peer sees one address and port whichever socket sent.
func TestConnSocksSourceMatchesListener(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	la, err := u.LocalAddr()
	require.NoError(t, err)
	for _, p := range []struct{ network, addr string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		peer, dst := newEstablishedPeer(t, u, p.network, p.addr)
		require.NoError(t, u.WriteTo([]byte("probe"), dst))
		require.Nil(t, u.connSockFor(dst))
		viaListener := readFrom(t, peer, 1)[0]
		assert.Equal(t, la.Port(), viaListener.Port())

		bufs, addrs := run(dst, u.socks.cfg.run, p.network)
		_, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		s := u.connSockFor(dst)
		require.NotNil(t, s, "no connected socket to %v", dst)
		for _, from := range readFrom(t, peer, len(bufs)) {
			assert.Equal(t, viaListener, from, "source seen by %v", dst)
		}
		local := s.conn.LocalAddr().(*net.UDPAddr).AddrPort()
		assert.Equal(t, viaListener, netip.AddrPortFrom(local.Addr().Unmap(), local.Port()))
	}
}

// A run long enough opens a connected socket per peer, its replies reach the listener's reader, and a peer that
// goes away sends its traffic back through the listener with its connected socket closed, while the next peer gets
// a connected socket of its own.
func TestConnSocks(t *testing.T) {
	var mu sync.Mutex
	got := map[netip.AddrPort]int{}
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, func(addr netip.AddrPort, _ []byte) {
		mu.Lock()
		got[addr]++
		mu.Unlock()
	})
	la, err := u.LocalAddr()
	require.NoError(t, err)
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), la.Port())

	var peers [3]*net.UDPConn
	var dsts [3]netip.AddrPort
	for i := range peers {
		peers[i], dsts[i] = newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	}
	for i, dst := range dsts[:2] {
		bufs, addrs := run(dst, u.socks.cfg.run, fmt.Sprint("p", i))
		n, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		assert.Equal(t, len(bufs), n)
		require.NotNil(t, u.connSockFor(dst), "no connected socket to peer %d", i)
		for _, from := range readFrom(t, peers[i], len(bufs)) {
			assert.Equal(t, to, from)
		}
		for range 3 {
			_, err := peers[i].WriteToUDPAddrPort([]byte("reply"), to)
			require.NoError(t, err)
		}
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got[dsts[0]] == 3 && got[dsts[1]] == 3
	}, 5*time.Second, time.Millisecond)

	// The peer's ICMP port unreachable surfaces on the connected socket's next call. The deadline is generous
	// because xnu rate-limits and delivers the unreachable on its own schedule.
	gone := dsts[1]
	goneSock := u.connSockFor(gone)
	require.NoError(t, peers[1].Close())
	bufs, addrs := run(gone, u.socks.cfg.run, "gone")
	require.Eventually(t, func() bool {
		_, _ = u.WriteBatch(bufs, addrs)
		return u.connSockFor(gone) == nil
	}, 10*time.Second, 10*time.Millisecond)
	assert.NotNil(t, u.connSockFor(dsts[0]))
	u.socks.closers.Wait()
	_, err = goneSock.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "closed connected socket left open")

	bufs, addrs = run(dsts[2], u.socks.cfg.run, "p2")
	_, err = u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	require.NotNil(t, u.connSockFor(dsts[2]))
	for _, from := range readFrom(t, peers[2], len(bufs)) {
		assert.Equal(t, to, from)
	}

	require.NoError(t, u.Rebind())
	for _, dst := range dsts {
		assert.Nil(t, u.connSockFor(dst), "connected socket left after Rebind")
	}
}

// Listen routines on one port share one set of connected sockets: the cap and the open bucket are theirs together,
// a peer's connected socket carries every routine's sends to it, and Rebind on the first routine, which is all
// Control.RebindUDPServer calls, clears every routine's listener and closes the connected sockets.
func TestConnSocksSharedAcrossRoutines(t *testing.T) {
	s := listen("0.0.0.0:0")
	s.Multi = true
	u0 := newConnSockListener(t, s, nil, nil, func(c *connSockConfig) { c.max = 1 })
	la, err := u0.LocalAddr()
	require.NoError(t, err)
	s.Listen = netip.AddrPortFrom(s.Listen.Addr(), la.Port())
	u1 := newConnSockListener(t, s, nil, nil)
	require.Same(t, u0.socks, u1.socks)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	peerA, a := newPeer(t, "udp4", "127.0.0.1:0")
	peerB, b := newPeer(t, "udp4", "127.0.0.1:0")
	for _, dst := range []netip.AddrPort{a, b} {
		// Nebula tells every writer.
		u0.SetEstablishedPeer(dst, true)
		u1.SetEstablishedPeer(dst, true)
	}

	bufs, addrs := run(a, u1.socks.cfg.run, "a")
	_, err = u1.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peerA, len(bufs))
	s1 := u1.connSockFor(a)
	require.NotNil(t, s1)
	var sends atomic.Int64
	s1.sys = func(fd int, b []byte) error {
		sends.Add(1)
		return writeFd(fd, b)
	}
	require.NoError(t, u0.WriteTo([]byte("via u0"), a))
	readFrom(t, peerA, 1)
	assert.EqualValues(t, 1, sends.Load(), "routine 0 didn't send on routine 1's connected socket")

	bufs, addrs = run(b, 2*u0.socks.cfg.run, "b")
	_, err = u0.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peerB, len(bufs))
	assert.Nil(t, u0.connSockFor(b), "a second connected socket past a cap of 1")

	level, opt := unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	if u0.isV4 {
		level, opt = unix.IPPROTO_IP, unix.IP_BOUND_IF
	}
	boundIf := func(u *StdConn) int {
		v, err := unix.GetsockoptInt(int(u.sysFd), level, opt)
		require.NoError(t, err)
		return v
	}
	for _, u := range []*StdConn{u0, u1} {
		require.NoError(t, unix.SetsockoptInt(int(u.sysFd), level, opt, lo.Index))
		require.Equal(t, lo.Index, boundIf(u))
	}
	require.NoError(t, u0.Rebind())
	assert.Zero(t, boundIf(u0))
	assert.Zero(t, boundIf(u1), "Rebind left routine 1 scoped")
	assert.Nil(t, u1.connSockFor(a), "Rebind left routine 1's connected socket open")
	u0.socks.closers.Wait()
	_, err = s1.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed)
}

// A connected socket on a specific listen.host would need SO_REUSEPORT on the listener, so connected sockets stay
// off there unless listen routines already set it.
func TestConnSocksSpecificHost(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprint("multi=", multi), func(t *testing.T) {
			s := listen("127.0.0.1:0")
			s.Multi = multi
			u := newConnSockListener(t, s, nil, nil)
			la, err := u.LocalAddr()
			require.NoError(t, err)
			if !multi {
				assert.Zero(t, reusePort(t, u.UDPConn), "listener")
			}
			peer, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
			bufs, addrs := run(dst, u.socks.cfg.run, "p")
			_, err = u.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			for _, from := range readFrom(t, peer, len(bufs)) {
				assert.Equal(t, la, from)
			}
			if multi {
				assert.NotNil(t, u.connSockFor(dst))
			} else {
				assert.Nil(t, u.connSockFor(dst))
			}
		})
	}
}

// A v4 listener can't send to a v6 destination; however often it's asked, it says so and opens no connected
// socket.
func TestConnSocksV6DestinationOnV4Listener(t *testing.T) {
	s := listen("127.0.0.1:0")
	s.Multi = true
	u := newConnSockListener(t, s, nil, nil)
	require.True(t, u.isV4)
	dst := netip.MustParseAddrPort("[::1]:9")
	u.SetEstablishedPeer(dst, true)
	bufs, _ := run(dst, 2*u.socks.cfg.run, "v6")
	for _, b := range bufs {
		assert.ErrorIs(t, u.WriteTo(b, dst), ErrInvalidIPv6RemoteForSocket)
	}
	assert.Nil(t, u.connSockFor(dst))
}

// darwin's tun hands over one packet per read, so a busy peer's traffic reaches the socket as single WriteTo
// calls. cfg.run of them inside one window earn a connected socket; the same count spread over more than a window
// doesn't.
func TestConnSocksOpenFromWriteTo(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	var now atomic.Int64
	now.Store(int64(time.Hour))
	u.socks.clock = now.Load
	_, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	pkt := []byte("pkt")

	for range u.socks.cfg.run - 1 {
		require.NoError(t, u.WriteTo(pkt, dst))
	}
	now.Add(int64(u.socks.cfg.window) + 1)
	require.NoError(t, u.WriteTo(pkt, dst))
	assert.Nil(t, u.connSockFor(dst), "a connected socket for sends spread over two windows")

	for range u.socks.cfg.run - 2 {
		require.NoError(t, u.WriteTo(pkt, dst))
	}
	assert.Nil(t, u.connSockFor(dst))
	require.NoError(t, u.WriteTo(pkt, dst))
	assert.NotNil(t, u.connSockFor(dst), "no connected socket after %d sends in one window", u.socks.cfg.run)
}

// Only the remote of an established tunnel gets a connected socket, however busy another destination is, and one
// that stops being established loses its connected socket and has to be busy again to get a new one.
func TestConnSocksOnlyForEstablishedPeers(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	peer, dst := newPeer(t, "udp4", "127.0.0.1:0")
	run1 := u.socks.cfg.run
	send := func(n int) {
		t.Helper()
		bufs, addrs := run(dst, n, "p")
		_, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		readFrom(t, peer, n)
	}

	send(2 * run1)
	assert.Nil(t, u.connSockFor(dst), "a connected socket for a busy destination with no tunnel")

	u.SetEstablishedPeer(dst, true)
	send(run1)
	s := u.connSockFor(dst)
	require.NotNil(t, s, "no connected socket for a busy established peer")

	u.SetEstablishedPeer(dst, false)
	assert.Nil(t, u.connSockFor(dst))
	u.socks.closers.Wait()
	_, err := s.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "connected socket left open after its tunnel went away")
	send(2 * run1)
	assert.Nil(t, u.connSockFor(dst), "a connected socket after the tunnel went away")

	u.SetEstablishedPeer(dst, true)
	send(run1 - 1)
	assert.Nil(t, u.connSockFor(dst), "a re-established peer kept its old count")
	send(1)
	assert.NotNil(t, u.connSockFor(dst))
}

// A tunnel going away while its busy remote is opening a connected socket never leaves one open, whether or not
// the remote is established again before the open finishes. The dial hook holds the open between reserving its
// destination and dialing until the tunnel has changed, so every round races.
func TestConnSocksEstablishedRace(t *testing.T) {
	h := &countingHandler{}
	u := newConnSockListener(t, listen("0.0.0.0:0"), h, nil, func(c *connSockConfig) {
		c.run = 1
		c.openEvery = time.Nanosecond
	})
	cs := u.socks
	peer, dst := newPeer(t, "udp4", "127.0.0.1:0")
	for i, reestablish := range []bool{false, true} {
		u.SetEstablishedPeer(dst, true)
		dialing, release := make(chan struct{}), make(chan struct{})
		cs.dialHook = func(netip.AddrPort) {
			close(dialing)
			<-release
		}
		done := make(chan error)
		go func() { done <- u.WriteTo([]byte("p"), dst) }()
		<-dialing
		u.SetEstablishedPeer(dst, false)
		if reestablish {
			u.SetEstablishedPeer(dst, true)
		}
		close(release)
		require.NoError(t, <-done)
		cs.dialHook = nil
		readFrom(t, peer, 1)

		assert.Nil(t, u.connSockFor(dst), "reestablish=%v", reestablish)
		assert.EqualValues(t, i+1, h.discarded.Load(), "reestablish=%v", reestablish)
		cs.mu.Lock()
		assert.Empty(t, cs.pending)
		cs.mu.Unlock()
		assert.Zero(t, cs.reserved.Load())
		u.SetEstablishedPeer(dst, false)
	}
	assert.Zero(t, h.opened.Load())
}

// Neither an open in flight nor a close holds anything SetEstablishedPeer waits on, since Nebula calls it under
// the hostmap's write lock; and a peer whose connected socket is still closing can't open another until the close
// completes. The hooks hold the open in its dials and the close before its Close.
func TestConnSocksSetEstablishedPeerMakesNoSyscalls(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil, func(c *connSockConfig) { c.openEvery = time.Nanosecond })
	cs := u.socks
	peer, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	_, other := newPeer(t, "udp4", "127.0.0.1:0")

	dialing, releaseDial := make(chan struct{}), make(chan struct{})
	cs.dialHook = func(netip.AddrPort) {
		close(dialing)
		<-releaseDial
	}
	opened := make(chan *connSock)
	go func() {
		bufs, addrs := run(dst, cs.cfg.run, "p")
		_, _ = u.WriteBatch(bufs, addrs)
		opened <- u.connSockFor(dst)
	}()
	<-dialing
	u.SetEstablishedPeer(other, true)
	u.SetEstablishedPeer(other, false)
	close(releaseDial)
	s := <-opened
	require.NotNil(t, s)
	readFrom(t, peer, cs.cfg.run)
	cs.dialHook = nil

	closing, releaseClose := make(chan struct{}), make(chan struct{})
	cs.closeHook = func(netip.AddrPort) {
		close(closing)
		<-releaseClose
	}
	u.SetEstablishedPeer(dst, false)
	<-closing
	assert.Nil(t, u.connSockFor(dst))
	u.SetEstablishedPeer(dst, true)
	bufs, addrs := run(dst, 2*cs.cfg.run, "q")
	_, err := u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peer, len(bufs))
	assert.Nil(t, u.connSockFor(dst), "a connected socket opened while the last one to its peer was closing")

	close(releaseClose)
	cs.closers.Wait()
	cs.closeHook = nil
	_, err = s.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed)
	bufs, addrs = run(dst, cs.cfg.run, "r")
	_, err = u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peer, len(bufs))
	assert.NotNil(t, u.connSockFor(dst), "no connected socket once the last one closed")
}

// A listener whose interface scope can't be read gives a busy peer no connected socket, rather than one without
// the scope; the peer stays on the listener for the backoff. A pipe stands in for the listener's descriptor, so
// getsockopt fails with ENOTSOCK.
func TestConnSocksBoundIfFailsClosed(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	_, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	var pipe [2]int
	require.NoError(t, unix.Pipe(pipe[:]))
	t.Cleanup(func() {
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
	})
	listener := u.sysFd
	u.sysFd = uintptr(pipe[0])
	s := u.maybeOpenConnSock(u.socks.peer(dst), dst, u.socks.cfg.run)
	u.sysFd = listener
	assert.Nil(t, s)
	assert.Nil(t, u.connSockFor(dst))
	assert.Greater(t, u.socks.peer(dst).retryAt, u.socks.clock(), "no backoff after a failed open")
}

// readTags reads n datagrams at peer and returns their payloads.
func readTags(t *testing.T, peer *net.UDPConn, n int) []string {
	t.Helper()
	buf := make([]byte, MTU)
	var tags []string
	for range n {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
		m, _, err := peer.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		tags = append(tags, string(buf[:m]))
	}
	return tags
}

// One batch can hold runs to a peer with a connected socket, to an established peer without one, and to a
// destination that is no tunnel's remote, interleaved; each run goes out its own way, in order, and all count.
func TestConnSocksWriteBatchMixedDestinations(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	s, peerA := openConnSock(t, u)
	peerB, b := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	peerC, c := newPeer(t, "udp4", "127.0.0.1:0")
	var onSock atomic.Int64
	s.sys = func(fd int, b []byte) error {
		onSock.Add(1)
		return writeFd(fd, b)
	}

	var bufs [][]byte
	var addrs []netip.AddrPort
	for _, r := range []struct {
		dst netip.AddrPort
		tag string
		n   int
	}{{s.dst, "a", 3}, {b, "b", 2}, {c, "c", 2}, {s.dst, "A", 2}, {c, "C", 1}} {
		for i := range r.n {
			bufs = append(bufs, fmt.Appendf(nil, "%s%d", r.tag, i))
			addrs = append(addrs, r.dst)
		}
	}
	n, err := u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	assert.Equal(t, len(bufs), n)
	assert.EqualValues(t, 5, onSock.Load(), "datagrams on a's connected socket")
	assert.Equal(t, []string{"a0", "a1", "a2", "A0", "A1"}, readTags(t, peerA, 5))
	assert.Equal(t, []string{"b0", "b1"}, readTags(t, peerB, 2))
	assert.Equal(t, []string{"c0", "c1", "C0"}, readTags(t, peerC, 3))
	assert.Nil(t, u.connSockFor(b))
}

// A connected socket error that doesn't mean the path is gone costs only its datagram: WriteBatch skips it and
// sends the rest of the run on the connected socket, WriteTo returns it, and the connected socket stays open.
func TestConnSocksWriteError(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	s, peer := openConnSock(t, u)
	s.sys = func(fd int, b []byte) error {
		if string(b) == "bad" {
			return syscall.EMSGSIZE
		}
		return writeFd(fd, b)
	}
	bufs := [][]byte{[]byte("ok0"), []byte("bad"), []byte("ok2")}
	n, err := u.WriteBatch(bufs, []netip.AddrPort{s.dst, s.dst, s.dst})
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []string{"ok0", "ok2"}, readTags(t, peer, 2))
	assert.ErrorIs(t, u.WriteTo([]byte("bad"), s.dst), syscall.EMSGSIZE)
	assert.Same(t, s, u.connSockFor(s.dst))
}

// A connected socket that turns out closed or dead partway through a run leaves the rest of the run to the
// listener, in order and all counted; a dead one is closed and its peer backs off to the listener.
func TestConnSocksWriteBatchFallsBackMidRun(t *testing.T) {
	for _, fail := range []error{net.ErrClosed, syscall.ECONNREFUSED} {
		t.Run(fail.Error(), func(t *testing.T) {
			u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
			s, peer := openConnSock(t, u)
			var calls atomic.Int64
			s.sys = func(fd int, b []byte) error {
				if calls.Add(1) > 2 {
					return fail
				}
				return writeFd(fd, b)
			}
			bufs, addrs := run(s.dst, 5, "r")
			n, err := u.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			assert.Equal(t, 5, n)
			assert.Equal(t, []string{"r-0", "r-1", "r-2", "r-3", "r-4"}, readTags(t, peer, 5))
			assert.EqualValues(t, 3, calls.Load(), "the connected socket was tried again after it failed")
			if fail == syscall.ECONNREFUSED {
				assert.Nil(t, u.connSockFor(s.dst))
				u.socks.mu.Lock()
				assert.Greater(t, u.socks.peer(s.dst).retryAt, u.socks.clock(), "no backoff after a dead connected socket")
				u.socks.mu.Unlock()
			}
		})
	}
}

// openConnSock earns a connected socket to a fresh loopback peer and returns it and the peer.
func openConnSock(t *testing.T, u *StdConn) (*connSock, *net.UDPConn) {
	t.Helper()
	peer, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
	bufs, addrs := run(dst, u.socks.cfg.run, "p")
	_, err := u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peer, len(bufs))
	s := u.connSockFor(dst)
	require.NotNil(t, s)
	return s, peer
}

// A flow-controlled interface makes a connected socket's sends wait, up to cfg.enobufsMax without one going
// through; after that each datagram is dropped without waiting until a send succeeds again, and each stall logs
// its drops once. s.sys stands in for an interface that answers every write with ENOBUFS until enobufs is
// cleared, and each sleep advances the clock.
func TestConnSockWriteENOBUFS(t *testing.T) {
	h := &countingHandler{}
	u := newConnSockListener(t, listen("0.0.0.0:0"), h, nil)
	s, _ := openConnSock(t, u)
	var now atomic.Int64
	now.Store(int64(time.Hour))
	sleeps := 0
	u.socks.clock = now.Load
	u.socks.sleep = func(d time.Duration) {
		sleeps++
		now.Add(int64(d))
	}
	var enobufs atomic.Bool
	s.sys = func(fd int, b []byte) error {
		if enobufs.Load() {
			return syscall.ENOBUFS
		}
		return writeFd(fd, b)
	}
	perStall := int(u.socks.cfg.enobufsMax / enobufsWait)
	bufs, _ := run(s.dst, 3, "q")

	for stall := 1; stall <= 2; stall++ {
		enobufs.Store(true)
		sent, errno, closed := u.connSockWrite(s, bufs)
		assert.Equal(t, 3, sent)
		assert.Zero(t, errno)
		assert.False(t, closed)
		assert.Equal(t, stall*perStall, sleeps)

		sent, _, _ = u.connSockWrite(s, bufs)
		assert.Equal(t, 3, sent)
		assert.Equal(t, stall*perStall, sleeps, "a stalled connected socket waited again")
		assert.EqualValues(t, stall, h.dropping.Load(), "drop log lines after stall %d", stall)

		enobufs.Store(false)
		sent, _, _ = u.connSockWrite(s, bufs[:1])
		assert.Equal(t, 1, sent)
		assert.Zero(t, s.stallAt.Load())
	}
}

// Concurrent writers share one ENOBUFS budget measured from the first ENOBUFS since a send went through: two
// writers stalled together wait as long as one would, and a send going through while a writer sleeps gives that
// writer a fresh budget. The sleep hook parks each writer until the test has moved the clock.
func TestConnSockWriteENOBUFSConcurrentWriters(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	s, _ := openConnSock(t, u)
	var now atomic.Int64
	u.socks.clock = now.Load
	asleep, wake := make(chan struct{}), make(chan struct{})
	u.socks.sleep = func(time.Duration) {
		asleep <- struct{}{}
		<-wake
	}
	// Datagrams starting with 'e' get ENOBUFS while enobufs is set; the rest go out.
	var enobufs atomic.Bool
	var wrote atomic.Int64
	s.sys = func(fd int, b []byte) error {
		if b[0] == 'e' && enobufs.Load() {
			return syscall.ENOBUFS
		}
		wrote.Add(1)
		return writeFd(fd, b)
	}
	write := func(tag string, done chan<- int) {
		sent, _, _ := u.connSockWrite(s, [][]byte{[]byte(tag)})
		done <- sent
	}
	budget := int64(u.socks.cfg.enobufsMax)

	t.Run("a send going through ends the stall", func(t *testing.T) {
		enobufs.Store(true)
		now.Store(int64(time.Hour))
		done := make(chan int)
		go write("e1", done)
		<-asleep
		now.Add(budget / 2)
		sent, _, _ := u.connSockWrite(s, [][]byte{[]byte("ok")})
		require.Equal(t, 1, sent)
		now.Add(budget)
		wake <- struct{}{}
		<-asleep // e1 hit ENOBUFS again 1.5x the budget after its first, and waited instead of dropping.
		enobufs.Store(false)
		before := wrote.Load()
		wake <- struct{}{}
		assert.Equal(t, 1, <-done)
		assert.Equal(t, before+1, wrote.Load(), "e1 was dropped")
	})

	t.Run("two stalled writers spend one budget", func(t *testing.T) {
		enobufs.Store(true)
		now.Store(int64(2 * time.Hour))
		done := make(chan int)
		go write("e2", done)
		go write("e3", done)
		<-asleep
		<-asleep
		now.Add(budget * 6 / 10)
		wake <- struct{}{}
		wake <- struct{}{}
		<-asleep // Both are 0.6x the budget into one stall, not 1.2x, so both wait again.
		<-asleep
		now.Add(budget / 2)
		before := wrote.Load()
		wake <- struct{}{}
		wake <- struct{}{}
		assert.Equal(t, 1, <-done)
		assert.Equal(t, 1, <-done)
		assert.Equal(t, before, wrote.Load(), "a datagram went out while ENOBUFS lasted")
	})
}

// A full send buffer that never drains parks a connected socket send only for cfg.enobufsMax, the stall budget
// ENOBUFS gets: golang/go#73919 has darwin UDP writes parked on EAGAIN waiting forever. Past it the datagrams are
// dropped and counted as sent, concurrent writers spend that one budget, and once a send goes through the
// connected socket works as before. s.sys stands in for a send buffer that stays full while eagain is set.
func TestConnSockWriteEAGAINBounded(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	s, peer := openConnSock(t, u)
	var eagain atomic.Bool
	eagain.Store(true)
	s.sys = func(fd int, b []byte) error {
		if eagain.Load() {
			return syscall.EAGAIN
		}
		return writeFd(fd, b)
	}
	budget := u.socks.cfg.enobufsMax

	start := time.Now()
	sent, errno, closed := u.connSockWrite(s, [][]byte{[]byte("x")})
	elapsed := time.Since(start)
	assert.Equal(t, 1, sent)
	assert.Zero(t, errno)
	assert.False(t, closed)
	assert.GreaterOrEqual(t, elapsed, budget, "the send didn't wait for the buffer to drain")
	assert.Less(t, elapsed, time.Second, "the send waited past its deadline")

	// The budget is spent, so these drop without waiting, however many writers there are.
	var wg sync.WaitGroup
	start = time.Now()
	for range 4 {
		wg.Go(func() {
			bufs, _ := run(s.dst, 8, "y")
			sent, _, _ := u.connSockWrite(s, bufs)
			assert.Equal(t, 8, sent)
		})
	}
	wg.Wait()
	assert.Less(t, time.Since(start), time.Second)

	// A send going through starts a fresh budget, which two writers stalled together spend once; the upper bound
	// is far looser than that, so a descheduled runner doesn't fail it.
	eagain.Store(false)
	sent, _, _ = u.connSockWrite(s, [][]byte{[]byte("ok")})
	require.Equal(t, 1, sent)
	readTags(t, peer, 1)
	eagain.Store(true)
	start = time.Now()
	for range 2 {
		wg.Go(func() {
			sent, _, _ := u.connSockWrite(s, [][]byte{[]byte("w")})
			assert.Equal(t, 1, sent)
		})
	}
	wg.Wait()
	elapsed = time.Since(start)
	assert.GreaterOrEqual(t, elapsed, budget)
	assert.Less(t, elapsed, time.Second)

	eagain.Store(false)
	bufs, addrs := run(s.dst, 3, "z")
	n, err := u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, []string{"z-0", "z-1", "z-2"}, readTags(t, peer, 3))
	assert.Zero(t, s.stallAt.Load())
	assert.Same(t, s, u.connSockFor(s.dst))
}

// A send waiting out ENOBUFS holds nothing a close or Close needs, and returns closed once it wakes to a closed
// connected socket. The sleep hook parks the writer until both closes have finished; after the close, s.sys
// writes for real, so the closed descriptor answers.
func TestConnSockWriteDoesNotBlockClose(t *testing.T) {
	u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil)
	s, _ := openConnSock(t, u)
	asleep, wake := make(chan struct{}), make(chan struct{})
	u.socks.sleep = func(time.Duration) {
		asleep <- struct{}{}
		<-wake
	}
	var gone atomic.Bool
	s.sys = func(fd int, b []byte) error {
		if gone.Load() {
			return writeFd(fd, b)
		}
		return syscall.ENOBUFS
	}
	done := make(chan bool)
	go func() {
		bufs, _ := run(s.dst, 1, "q")
		_, _, closed := u.connSockWrite(s, bufs)
		done <- closed
	}()
	<-asleep

	u.closeConnSock(s, "test", false)
	u.socks.closers.Wait()
	require.NoError(t, u.Close())
	gone.Store(true)
	close(wake)
	assert.True(t, <-done, "the writer didn't see its connected socket close")
}

// countingHandler counts connected socket open, close, discard and ENOBUFS drop log lines.
type countingHandler struct{ opened, closed, discarded, dropping atomic.Int64 }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	switch r.Message {
	case "connected socket: opened":
		h.opened.Add(1)
	case "connected socket: closed":
		h.closed.Add(1)
	case "connected socket: discarded, its tunnel or route changed while it opened":
		h.discarded.Add(1)
	case "connected socket: sends stalled, dropping datagrams until one goes through":
		h.dropping.Add(1)
	}
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

// Anyone can make Nebula reply to them, as recv_error does to every datagram with an unknown index; the reader
// below stands in for that reply. However many replies a sender draws, it never earns a connected socket without
// an established tunnel.
func TestConnSocksNoneForUnestablishedSenders(t *testing.T) {
	h := &countingHandler{}
	reply := []byte("reply")
	var c *StdConn
	var ready atomic.Bool
	c = newConnSockListener(t, listen("0.0.0.0:0"), h, func(from netip.AddrPort, _ []byte) {
		if ready.Load() {
			_ = c.WriteTo(reply, from)
		}
	})
	ready.Store(true)
	la, err := c.LocalAddr()
	require.NoError(t, err)
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), la.Port())
	pkt := []byte("junk")
	buf := make([]byte, 64)
	for range 10 {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		for range 2 * c.socks.cfg.run {
			_, err := pc.WriteToUDPAddrPort(pkt, to)
			require.NoError(t, err)
			require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, _, err = pc.ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
		}
		_ = pc.Close()
	}
	assert.Zero(t, h.opened.Load())
	assert.Nil(t, c.socks.table.Load())
}

// Established peers that keep going away churn connected sockets at most as fast as the open bucket allows, and
// what connSocks keeps about each goes when its tunnel does. Each round a fresh peer is established, gets busy and
// goes away, and the clock moves 10ms.
func TestConnSocksChurnBounded(t *testing.T) {
	h := &countingHandler{}
	u := newConnSockListener(t, listen("0.0.0.0:0"), h, nil)
	var now atomic.Int64
	now.Store(int64(time.Hour))
	u.socks.clock = now.Load
	const rounds, step = 300, 10 * time.Millisecond
	for range rounds {
		peer, dst := newEstablishedPeer(t, u, "udp4", "127.0.0.1:0")
		bufs, addrs := run(dst, u.socks.cfg.run, "p")
		n, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		require.Equal(t, len(bufs), n)
		readFrom(t, peer, len(bufs))
		u.SetEstablishedPeer(dst, false)
		u.socks.closers.Wait()
		require.NoError(t, peer.Close())
		now.Add(int64(step))
	}
	elapsed := time.Duration(rounds) * step
	budget := int64(u.socks.cfg.max) + int64(elapsed/u.socks.cfg.openEvery) + 1
	t.Logf("%d rounds over %v: %d opens, %d closes", rounds, elapsed, h.opened.Load(), h.closed.Load())
	require.GreaterOrEqual(t, h.opened.Load(), int64(u.socks.cfg.max), "the rounds never churned")
	require.LessOrEqual(t, h.opened.Load(), budget)
	assert.Equal(t, h.opened.Load(), h.closed.Load())
	assert.Nil(t, u.socks.table.Load(), "peers left after their tunnels went away")
	assert.Zero(t, u.socks.reserved.Load())
}

// No send allocates, down any path: the listener with connected sockets off, to a destination that is no
// tunnel's remote, to an established peer that isn't busy, or on a connected socket, one datagram or a run.
func TestConnSockSendsDontAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("-race makes sync.Pool drop writers at random, so connected sends allocate")
	}
	pkt := make([]byte, 1400)
	for _, c := range []struct {
		name  string
		cfg   func(*connSockConfig)
		setup func(u *StdConn, dst netip.AddrPort)
	}{
		{name: "off", cfg: func(c *connSockConfig) { c.max = 0 }},
		{name: "ineligible", setup: func(u *StdConn, dst netip.AddrPort) {
			u.SetEstablishedPeer(netip.AddrPortFrom(dst.Addr(), dst.Port()+1), true)
		}},
		{name: "eligible", cfg: func(c *connSockConfig) { c.run = 1 << 30 },
			setup: func(u *StdConn, dst netip.AddrPort) { u.SetEstablishedPeer(dst, true) }},
		{name: "connected", setup: func(u *StdConn, dst netip.AddrPort) {
			u.SetEstablishedPeer(dst, true)
			bufs, addrs := run(dst, u.socks.cfg.run, "p")
			_, err := u.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			require.NotNil(t, u.connSockFor(dst))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cfg []func(*connSockConfig)
			if c.cfg != nil {
				cfg = append(cfg, c.cfg)
			}
			u := newConnSockListener(t, listen("0.0.0.0:0"), nil, nil, cfg...)
			_, dst := newPeer(t, "udp4", "127.0.0.1:0")
			if c.setup != nil {
				c.setup(u, dst)
			}
			bufs, addrs := run(dst, 8, "b")
			assert.Zero(t, testing.AllocsPerRun(100, func() { _ = u.WriteTo(pkt, dst) }), "WriteTo")
			assert.Zero(t, testing.AllocsPerRun(100, func() { _, _ = u.WriteBatch(bufs, addrs) }), "WriteBatch")
		})
	}
}

// Once burst tokens are spent the bucket earns one back per interval.
func TestGCRA(t *testing.T) {
	var g gcra
	now := int64(time.Hour)
	for i := range 3 {
		require.True(t, g.take(now, 3, time.Second), "token %d of the burst", i)
	}
	require.False(t, g.take(now, 3, time.Second))
	require.False(t, g.take(now+int64(999*time.Millisecond), 3, time.Second))
	require.True(t, g.take(now+int64(time.Second), 3, time.Second))
	require.False(t, g.take(now+int64(time.Second), 3, time.Second))
	require.True(t, g.take(now+int64(time.Hour), 3, time.Second))
}
