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

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newLaneListener opens a listener with the lane knobs pinned to their defaults, so NEBULA_* variables in
// the environment can't change what a test sees, applies cfg, and starts ListenOut with r.
func newLaneListener(t *testing.T, s Settings, h slog.Handler, r EncReader, cfg ...func(*laneConfig)) *StdConn {
	t.Helper()
	for k, v := range map[string]string{
		"NEBULA_LANES":           "8",
		"NEBULA_LANE_RUN":        "64",
		"NEBULA_LANE_WINDOW":     "1s",
		"NEBULA_LANE_IDLE":       "30s",
		"NEBULA_LANE_OPEN_EVERY": "1s",
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
		f(&u.lanes.cfg)
	}
	go func() { _ = u.ListenOut(r, func() {}) }()
	require.Eventually(t, func() bool { return u.reader.Load() != nil }, time.Second, time.Millisecond)
	return u
}

func listen(s string) Settings { return Settings{Listen: netip.MustParseAddrPort(s)} }

// run builds n datagrams to dst, each long enough to count toward a lane.
func run(dst netip.AddrPort, n int, tag string) ([][]byte, []netip.AddrPort) {
	bufs := make([][]byte, n)
	addrs := make([]netip.AddrPort, n)
	for i := range bufs {
		bufs[i] = fmt.Appendf(make([]byte, 0, laneMinLen), "%-*s", laneMinLen, fmt.Sprint(tag, "-", i))
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

// readFrom reads n datagrams at peer and returns the source of each.
func readFrom(t *testing.T, peer *net.UDPConn, n int) []netip.AddrPort {
	t.Helper()
	buf := make([]byte, MTU)
	var from []netip.AddrPort
	for range n {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
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
		lc := net.ListenConfig{Control: laneControl(reuse == "reuseport", 0)}
		pc, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort(addr, fmt.Sprint(port)))
		if err == nil {
			_ = pc.Close()
			bound = append(bound, b)
		}
	}
	return bound
}

// The listener never sets SO_REUSEPORT, and a lane binds with it only to a specific address, so every bind a
// lone listener refuses is refused after NewListener returns and while lanes are open. Same-uid SO_REUSEPORT
// binds to a specific address are left out: xnu allows them beside a lone wildcard listener too, which is how
// a lane binds, and refuses them to any other uid.
func TestLanesNoSharedBind(t *testing.T) {
	u := newLaneListener(t, listen("0.0.0.0:0"), nil, nil)
	la, err := u.LocalAddr()
	require.NoError(t, err)
	binds := []string{
		"udp4 0.0.0.0 plain", "udp4 0.0.0.0 reuseport", "udp4 127.0.0.1 plain",
		"udp6 :: plain", "udp6 :: reuseport", "udp6 ::1 plain",
	}
	assert.Zero(t, reusePort(t, u.UDPConn), "listener")
	assert.Empty(t, rogueBinds(t, la.Port(), binds), "bound beside the listener")

	peer4, dst4 := newPeer(t, "udp4", "127.0.0.1:0")
	peer6, dst6 := newPeer(t, "udp6", "[::1]:0")
	for _, p := range []struct {
		c   *net.UDPConn
		dst netip.AddrPort
	}{{peer4, dst4}, {peer6, dst6}} {
		bufs, addrs := run(p.dst, u.lanes.cfg.run, "p")
		_, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		readFrom(t, p.c, len(bufs))
		l := u.laneFor(p.dst)
		require.NotNil(t, l, "no lane to %v", p.dst)
		assert.NotZero(t, reusePort(t, l.conn), "lane to %v", p.dst)
	}
	assert.Empty(t, rogueBinds(t, la.Port(), binds), "bound beside the lanes")
}

// A lane binds the source address the listener's route to its peer picks, for either family on a
// dual-stack listener, so the peer sees one address and port whichever socket sent.
func TestLanesSourceMatchesListener(t *testing.T) {
	u := newLaneListener(t, listen("0.0.0.0:0"), nil, nil)
	la, err := u.LocalAddr()
	require.NoError(t, err)
	for _, p := range []struct{ network, addr string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		peer, dst := newPeer(t, p.network, p.addr)
		require.NoError(t, u.WriteTo(make([]byte, laneMinLen), dst))
		require.Nil(t, u.laneFor(dst))
		viaListener := readFrom(t, peer, 1)[0]
		assert.Equal(t, la.Port(), viaListener.Port())

		bufs, addrs := run(dst, u.lanes.cfg.run, p.network)
		_, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		l := u.laneFor(dst)
		require.NotNil(t, l, "no lane to %v", dst)
		for _, from := range readFrom(t, peer, len(bufs)) {
			assert.Equal(t, viaListener, from, "source seen by %v", dst)
		}
		local := l.conn.LocalAddr().(*net.UDPAddr).AddrPort()
		assert.Equal(t, viaListener, netip.AddrPortFrom(local.Addr().Unmap(), local.Port()))
	}
}

// A run long enough opens a lane per peer, its replies reach the listener's reader, and a peer that goes
// away sends its traffic back through the listener with its lane closed, while the next peer gets a lane of
// its own.
func TestLanes(t *testing.T) {
	var mu sync.Mutex
	got := map[netip.AddrPort]int{}
	u := newLaneListener(t, listen("0.0.0.0:0"), nil, func(addr netip.AddrPort, _ []byte) {
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
		peers[i], dsts[i] = newPeer(t, "udp4", "127.0.0.1:0")
	}
	for i, dst := range dsts[:2] {
		bufs, addrs := run(dst, u.lanes.cfg.run, fmt.Sprint("p", i))
		n, err := u.WriteBatch(bufs, addrs)
		require.NoError(t, err)
		assert.Equal(t, len(bufs), n)
		require.NotNil(t, u.laneFor(dst), "no lane to peer %d", i)
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
	}, time.Second, time.Millisecond)

	// The peer's ICMP port unreachable surfaces on the lane's next call.
	gone := dsts[1]
	goneLane := u.laneFor(gone)
	require.NoError(t, peers[1].Close())
	bufs, addrs := run(gone, u.lanes.cfg.run, "gone")
	require.Eventually(t, func() bool {
		_, _ = u.WriteBatch(bufs, addrs)
		return u.laneFor(gone) == nil
	}, time.Second, 10*time.Millisecond)
	assert.NotNil(t, u.laneFor(dsts[0]))
	_, err = goneLane.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "released lane left open")

	bufs, addrs = run(dsts[2], u.lanes.cfg.run, "p2")
	_, err = u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	require.NotNil(t, u.laneFor(dsts[2]))
	for _, from := range readFrom(t, peers[2], len(bufs)) {
		assert.Equal(t, to, from)
	}

	require.NoError(t, u.Rebind())
	assert.Empty(t, *u.lanes.table.Load(), "lanes left after Rebind")
}

// A lane on a specific listen.host would need SO_REUSEPORT on the listener, so lanes stay off there unless
// listen routines already set it.
func TestLanesSpecificHost(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprint("multi=", multi), func(t *testing.T) {
			s := listen("127.0.0.1:0")
			s.Multi = multi
			u := newLaneListener(t, s, nil, nil)
			la, err := u.LocalAddr()
			require.NoError(t, err)
			if !multi {
				assert.Zero(t, reusePort(t, u.UDPConn), "listener")
			}
			peer, dst := newPeer(t, "udp4", "127.0.0.1:0")
			bufs, addrs := run(dst, u.lanes.cfg.run, "p")
			_, err = u.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			for _, from := range readFrom(t, peer, len(bufs)) {
				assert.Equal(t, la, from)
			}
			if multi {
				assert.NotNil(t, u.laneFor(dst))
			} else {
				assert.Nil(t, u.laneFor(dst))
			}
		})
	}
}

// A v4 listener can't send to a v6 destination; however often it's asked, it says so and opens no lane.
func TestLanesV6DestinationOnV4Listener(t *testing.T) {
	s := listen("127.0.0.1:0")
	s.Multi = true
	u := newLaneListener(t, s, nil, nil)
	require.True(t, u.isV4)
	dst := netip.MustParseAddrPort("[::1]:9")
	bufs, _ := run(dst, 2*u.lanes.cfg.run, "v6")
	for _, b := range bufs {
		assert.ErrorIs(t, u.WriteTo(b, dst), ErrInvalidIPv6RemoteForSocket)
	}
	assert.Nil(t, u.laneFor(dst))
}

// darwin's tun hands over one packet per read, so a busy peer's traffic reaches the socket as single
// WriteTo calls. cfg.run of them inside one window earn a lane; the same count spread over more than a
// window doesn't, and header-only datagrams such as recv_error replies don't count at all.
func TestLanesOpenFromWriteTo(t *testing.T) {
	u := newLaneListener(t, listen("0.0.0.0:0"), nil, nil, func(c *laneConfig) { c.window = 250 * time.Millisecond })
	_, dst := newPeer(t, "udp4", "127.0.0.1:0")
	pkt := make([]byte, laneMinLen)

	for range 2 * u.lanes.cfg.run {
		require.NoError(t, u.WriteTo(make([]byte, header.Len), dst))
	}
	assert.Nil(t, u.laneFor(dst), "a lane for header-only datagrams")

	for range u.lanes.cfg.run - 1 {
		require.NoError(t, u.WriteTo(pkt, dst))
	}
	time.Sleep(2 * u.lanes.cfg.window)
	require.NoError(t, u.WriteTo(pkt, dst))
	assert.Nil(t, u.laneFor(dst), "a lane for sends spread over two windows")

	for range u.lanes.cfg.run - 1 {
		require.NoError(t, u.WriteTo(pkt, dst))
	}
	assert.NotNil(t, u.laneFor(dst), "no lane after %d sends in one window", u.lanes.cfg.run)
}

// openLane earns a lane to a fresh loopback peer.
func openLane(t *testing.T, u *StdConn) *lane {
	t.Helper()
	peer, dst := newPeer(t, "udp4", "127.0.0.1:0")
	bufs, addrs := run(dst, u.lanes.cfg.run, "p")
	_, err := u.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	readFrom(t, peer, len(bufs))
	l := u.laneFor(dst)
	require.NotNil(t, l)
	return l
}

// A flow-controlled interface makes a lane's sends wait, up to cfg.enobufsMax without one going through;
// after that each datagram is dropped without waiting until a send succeeds again. l.send stands in for an
// interface that answers every write with ENOBUFS until enobufs is cleared.
func TestLaneWriteENOBUFS(t *testing.T) {
	u := newLaneListener(t, listen("0.0.0.0:0"), nil, nil)
	l := openLane(t, u)
	var enobufs atomic.Bool
	enobufs.Store(true)
	l.send = func(fd int, b []byte) error {
		if enobufs.Load() {
			return syscall.ENOBUFS
		}
		return writeFd(fd, b)
	}

	bufs, _ := run(l.dst, 3, "q")
	sent, errno, closed := u.laneWrite(l, bufs)
	assert.Equal(t, 3, sent)
	assert.Zero(t, errno)
	assert.False(t, closed)
	stalled := l.stalled.Load()
	assert.GreaterOrEqual(t, stalled, int64(u.lanes.cfg.enobufsMax))

	sent, _, _ = u.laneWrite(l, bufs)
	assert.Equal(t, 3, sent)
	assert.Equal(t, stalled, l.stalled.Load(), "a stalled lane waited again")

	enobufs.Store(false)
	sent, _, _ = u.laneWrite(l, bufs[:1])
	assert.Equal(t, 1, sent)
	assert.Zero(t, l.stalled.Load())
}

// Neither a send waiting out ENOBUFS nor one parked on a full buffer holds anything a release or Close needs,
// and both return once the lane is closed. cfg.enobufsMax is far longer than the test so that only the close
// can end the ENOBUFS wait. The EAGAIN writer parks in the netpoller until the close evicts the descriptor,
// or spins through RawConn.Write if kqueue reports the socket writable again; the 10ms sleep gives it time to
// park.
func TestLaneWriteDoesNotBlockClose(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOBUFS, syscall.EAGAIN} {
		t.Run(errno.Error(), func(t *testing.T) {
			u := newLaneListener(t, listen("0.0.0.0:0"), nil, nil, func(c *laneConfig) { c.enobufsMax = time.Hour })
			l := openLane(t, u)
			var calls atomic.Int64
			l.send = func(int, []byte) error {
				calls.Add(1)
				return errno
			}
			done := make(chan bool)
			go func() {
				bufs, _ := run(l.dst, 1, "q")
				_, _, closed := u.laneWrite(l, bufs)
				done <- closed
			}()
			require.Eventually(t, func() bool { return calls.Load() > 0 }, time.Second, time.Millisecond)
			time.Sleep(10 * time.Millisecond)

			start := time.Now()
			u.releaseLane(l, "test", false)
			assert.Less(t, time.Since(start), 100*time.Millisecond, "release waited for the writer")
			select {
			case closed := <-done:
				assert.True(t, closed)
			case <-time.After(time.Second):
				t.Fatal("writer still waiting after its lane closed")
			}
			start = time.Now()
			require.NoError(t, u.Close())
			assert.Less(t, time.Since(start), 100*time.Millisecond)
		})
	}
}

// countingHandler counts lane open and release log lines.
type countingHandler struct{ opened, released atomic.Int64 }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	switch r.Message {
	case "lanes: opened":
		h.opened.Add(1)
	case "lanes: released":
		h.released.Add(1)
	}
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

// An unauthenticated sender can make Nebula reply to it, as recv_error does to every datagram with an
// unknown index: the reader below stands in for that reply, replyLen bytes long. Each round sends cfg.run
// datagrams from a fresh loopback port, reads the replies and closes it; the extra WriteTo stands in for the
// reply to one more datagram forged from that port, which draws an ICMP port unreachable, so a lane is
// released with a backoff for a destination that never returns. The round waits for its replies before
// closing because xnu suppresses repeat port unreachables to one port, and a listener reply landing on the
// closed port first would use up the one the lane needs.
func churn(t *testing.T, replyLen int) (h *countingHandler, u *StdConn, elapsed time.Duration) {
	h = &countingHandler{}
	reply := make([]byte, replyLen)
	var c *StdConn
	var ready atomic.Bool
	c = newLaneListener(t, listen("0.0.0.0:0"), h, func(from netip.AddrPort, _ []byte) {
		if ready.Load() {
			_ = c.WriteTo(reply, from)
		}
	}, func(c *laneConfig) { c.backoff = 20 * time.Millisecond })
	ready.Store(true)
	la, err := c.LocalAddr()
	require.NoError(t, err)
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), la.Port())

	const rounds = 100
	pkt := make([]byte, header.Len)
	start := time.Now()
	for range rounds {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		for range c.lanes.cfg.run {
			_, err := pc.WriteToUDPAddrPort(pkt, to)
			require.NoError(t, err)
		}
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Second)))
		buf := make([]byte, 64)
		for range c.lanes.cfg.run {
			_, _, err := pc.ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
		}
		src := pc.LocalAddr().(*net.UDPAddr).AddrPort()
		_ = pc.Close()
		time.Sleep(time.Millisecond)
		_ = c.WriteTo(reply, src)
		time.Sleep(time.Millisecond)
	}
	// Lanes whose last reply hit a closed port are released by their reader.
	time.Sleep(50 * time.Millisecond)
	elapsed = time.Since(start)
	t.Logf("%d rounds in %v: %d opens, %d releases", rounds, elapsed.Round(time.Millisecond), h.opened.Load(),
		h.released.Load())
	return h, c, elapsed
}

// Header-only replies such as recv_error never earn a lane, however many senders draw them.
func TestLanesNoneFromRecvErrorReplies(t *testing.T) {
	h, _, _ := churn(t, header.Len)
	assert.Zero(t, h.opened.Load())
}

// Replies long enough to earn lanes churn them at most as fast as the open bucket allows, and the backoffs
// they leave are pruned once they run out.
func TestLanesChurnBounded(t *testing.T) {
	h, u, elapsed := churn(t, laneMinLen)
	budget := int64(u.lanes.cfg.max) + int64(elapsed/u.lanes.cfg.openEvery) + 1
	require.Positive(t, h.released.Load(), "no lane was released, so the rounds never churned")
	require.LessOrEqual(t, h.opened.Load(), budget)
	require.LessOrEqual(t, h.released.Load(), budget)

	time.Sleep(2 * u.lanes.cfg.backoff)
	u.lanes.pruneBackoff()
	u.lanes.mu.Lock()
	require.Empty(t, u.lanes.backoff)
	u.lanes.mu.Unlock()
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

// A spray of distinct destinations stops being tracked at laneSendsMax, while one already tracked still
// earns its lane.
func TestLanesSendsCapped(t *testing.T) {
	ls := &lanes{cfg: laneConfig{run: 2, window: time.Hour}}
	tracked := netip.MustParseAddrPort("192.0.2.1:4242")
	require.False(t, ls.busy(tracked, 1))
	for i := range laneSendsMax + 100 {
		ls.busy(netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(i)), 1)
	}
	require.Len(t, ls.sends, laneSendsMax)
	require.True(t, ls.busy(tracked, 1))
}
