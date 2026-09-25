//go:build !e2e_testing

package udp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/unix"
)

// A lane is a UDP socket connected to one busy peer, on the listener's port and bound to the source address
// the listener's route to that peer picks, so the peer sees the same address and port from either. A send on
// a connected socket skips the per-datagram address and MAC policy checks, and the EndpointSecurity send
// check that xprotectd can hold every unconnected sendto on, and it is the only UDP send that reports the
// interface queue's flow control, as ENOBUFS. A connected socket wins xnu's lookup for its peer's datagrams;
// it never sees anyone else's.
//
// A lane sets SO_REUSEPORT and binds a specific address beside a wildcard listener, which sets SO_REUSEPORT
// only for listen routines. xnu refuses a wildcard SO_REUSEPORT bind beside a holder without the option, and
// refuses another uid's bind to an address a socket holds specifically, so no other user can join the port
// while lanes open and close: uid nobody got EADDRINUSE on every bind against a root listener with lanes in
// the 09-25 probes. A lane is closed, never disconnected, because xnu widens a disconnected socket's local
// address to the wildcard.
type lane struct {
	dst  netip.AddrPort
	conn *net.UDPConn
	rc   syscall.RawConn
	// used is the monotonic time in nanoseconds of the lane's last send or receive.
	used atomic.Int64
	// stalled is how long, in nanoseconds, the lane's sends have waited out ENOBUFS since one last went
	// through.
	stalled atomic.Int64
	// send writes one datagram on the connected descriptor: writeFd, or a stand-in for the interface in tests.
	send func(fd int, b []byte) error
}

// laneConfig holds the knobs, read from the environment so one binary can be tuned without a rebuild.
type laneConfig struct {
	// max is how many lanes may be open at once; 0 turns lanes off.
	max int
	// run is how many datagrams to one destination within one window earn it a lane. darwin's tun hands
	// over one packet per read, so a peer's sends arrive one WriteTo or one-datagram batch at a time and
	// busyness has to be counted across calls.
	run    int
	window time.Duration
	// idle closes a lane after it has neither sent nor received for this long.
	idle time.Duration
	// backoff keeps a destination whose lane failed on the listener for this long.
	backoff time.Duration
	// openEvery is how often the open bucket earns back an open once max are spent, which bounds lane churn
	// however fast senders earn lanes and errors close them.
	openEvery time.Duration
	// enobufsMax is how long a lane's sends may wait out ENOBUFS without one going through before they drop
	// instead, so a suspended interface costs one write per datagram rather than stalling the tun reader.
	enobufsMax time.Duration
}

func laneConfigFromEnv() laneConfig {
	c := laneConfig{
		max:        8,
		run:        64,
		window:     time.Second,
		idle:       30 * time.Second,
		backoff:    30 * time.Second,
		openEvery:  time.Second,
		enobufsMax: 10 * time.Millisecond,
	}
	if v, err := strconv.Atoi(os.Getenv("NEBULA_LANES")); err == nil {
		c.max = v
	}
	if v, err := strconv.Atoi(os.Getenv("NEBULA_LANE_RUN")); err == nil && v > 0 {
		c.run = v
	}
	if v, err := time.ParseDuration(os.Getenv("NEBULA_LANE_WINDOW")); err == nil && v > 0 {
		c.window = v
	}
	if v, err := time.ParseDuration(os.Getenv("NEBULA_LANE_IDLE")); err == nil && v > 0 {
		c.idle = v
	}
	if v, err := time.ParseDuration(os.Getenv("NEBULA_LANE_OPEN_EVERY")); err == nil && v > 0 {
		c.openEvery = v
	}
	return c
}

type lanes struct {
	cfg laneConfig
	// off keeps lanes from opening, when the listener's address can't be shared with them.
	off atomic.Bool
	// table is read on every send without a lock; writers copy it under mu.
	table atomic.Pointer[map[netip.AddrPort]*lane]
	mu    sync.Mutex
	// backoff holds when each destination whose lane failed may try again.
	backoff map[netip.AddrPort]time.Time
	closed  bool
	// done stops the reaper; it is made when ListenOut starts the lanes.
	done chan struct{}
	// opens bounds lane opens to cfg.max at once and one per cfg.openEvery after.
	opens gcra
	// logs bounds lane log lines at info or warn; see laneLogBurst.
	logs gcra

	// sends counts datagrams to each destination without a lane since its window started.
	sendsMu sync.Mutex
	sends   map[netip.AddrPort]sendCount
}

type sendCount struct {
	start int64
	n     int
}

// laneSendsMax caps how many destinations busy tracks at once. Nebula answers any datagram with an unknown
// index with a recv_error, so a sprayer of spoofed sources would otherwise add an entry per packet until
// pruneSends catches up.
const laneSendsMax = 4096

// laneMinLen is the shortest datagram that counts toward busy: a header and a 16-byte AEAD tag, the least
// an encrypted tunnel message carries. recv_error replies and punches are shorter, and anyone can draw those to any
// address.
const laneMinLen = header.Len + 16

// laneLogBurst and laneLogEvery size the bucket that lets lane opens, releases and failures log at info or
// warn; past it they log at debug, so churn can't flood the log.
const (
	laneLogBurst = 32
	laneLogEvery = 10 * time.Second
)

var monoStart = time.Now()

func monoNow() int64 { return int64(time.Since(monoStart)) }

// gcra is a token bucket kept as the monotonic time it is next full (the generic cell rate algorithm), so it
// needs no refill tick.
type gcra struct{ tat int64 }

// take spends a token from a bucket of burst that earns one back per every, and reports whether there was
// one to spend.
func (g *gcra) take(now int64, burst int, every time.Duration) bool {
	e := int64(every)
	tat := max(g.tat, now)
	if tat-now > int64(burst-1)*e {
		return false
	}
	g.tat = tat + e
	return true
}

// logLevelLocked returns level while the log bucket has a token, and debug once it is spent.
func (ls *lanes) logLevelLocked(level slog.Level) slog.Level {
	if ls.logs.take(monoNow(), laneLogBurst, laneLogEvery) {
		return level
	}
	return slog.LevelDebug
}

// startLanes starts the idle reaper.
func (u *StdConn) startLanes() {
	ls := &u.lanes
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed || ls.done != nil || ls.cfg.max <= 0 || ls.off.Load() {
		return
	}
	ls.done = make(chan struct{})
	go u.reapLanes(ls.done)
}

// closeLanes closes every lane and keeps new ones from opening, for shutdown.
func (u *StdConn) closeLanes() {
	ls := &u.lanes
	ls.mu.Lock()
	if ls.closed {
		ls.mu.Unlock()
		return
	}
	ls.closed = true
	if ls.done != nil {
		close(ls.done)
	}
	ls.mu.Unlock()
	u.releaseLanes("close")
}

func (u *StdConn) laneFor(dst netip.AddrPort) *lane {
	t := u.lanes.table.Load()
	if t == nil {
		return nil
	}
	return (*t)[dst]
}

// full reports whether cfg.max lanes are open, so no destination can earn one.
func (ls *lanes) full() bool {
	t := ls.table.Load()
	return t != nil && len(*t) >= ls.cfg.max
}

// busy counts n more datagrams to dst and reports whether it has now sent cfg.run within one window. A
// busy destination's count starts over, so a peer that can't get a lane retries at most once per cfg.run
// sends.
func (ls *lanes) busy(dst netip.AddrPort, n int) bool {
	now := monoNow()
	ls.sendsMu.Lock()
	defer ls.sendsMu.Unlock()
	if ls.sends == nil {
		ls.sends = map[netip.AddrPort]sendCount{}
	}
	c, ok := ls.sends[dst]
	if !ok && len(ls.sends) >= laneSendsMax {
		return false
	}
	if !ok || time.Duration(now-c.start) > ls.cfg.window {
		c = sendCount{start: now}
	}
	c.n += n
	if c.n < ls.cfg.run {
		ls.sends[dst] = c
		return false
	}
	delete(ls.sends, dst)
	return true
}

// pruneSends forgets destinations whose window has run out, so peers that went quiet don't pile up.
func (ls *lanes) pruneSends() {
	now := monoNow()
	ls.sendsMu.Lock()
	defer ls.sendsMu.Unlock()
	for dst, c := range ls.sends {
		if time.Duration(now-c.start) > ls.cfg.window {
			delete(ls.sends, dst)
		}
	}
}

// pruneBackoff forgets backoffs that have run out, so destinations that never send again don't pile up.
func (ls *lanes) pruneBackoff() {
	now := time.Now()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for dst, until := range ls.backoff {
		if now.After(until) {
			delete(ls.backoff, dst)
		}
	}
}

// laneable reports whether a lane to dst could send what the listener would. A v4 listener can't reach a v6
// destination at all, and a lane bound to a specific listen.host must share its family.
func (u *StdConn) laneable(dst netip.AddrPort) bool {
	if !dst.IsValid() || dst.Port() == 0 {
		return false
	}
	if u.isV4 {
		return dst.Addr().Is4()
	}
	return u.listenHost.IsUnspecified() || u.listenHost.Unmap().Is4() == dst.Addr().Unmap().Is4()
}

// maybeOpenLane counts n datagrams to dst and opens a lane to it once it is busy and nothing rules a lane
// out.
func (u *StdConn) maybeOpenLane(dst netip.AddrPort, n int) *lane {
	ls := &u.lanes
	if n <= 0 || ls.cfg.max <= 0 || ls.off.Load() || u.reader.Load() == nil || !u.laneable(dst) || ls.full() ||
		!ls.busy(dst, n) {
		return nil
	}
	ls.mu.Lock()
	if ls.closed {
		ls.mu.Unlock()
		return nil
	}
	t := ls.table.Load()
	if t != nil {
		if l := (*t)[dst]; l != nil {
			ls.mu.Unlock()
			return l
		}
		if len(*t) >= ls.cfg.max {
			ls.mu.Unlock()
			return nil
		}
	}
	if until, ok := ls.backoff[dst]; ok {
		if time.Now().Before(until) {
			ls.mu.Unlock()
			return nil
		}
		delete(ls.backoff, dst)
	}
	if !ls.opens.take(monoNow(), ls.cfg.max, ls.cfg.openEvery) {
		ls.mu.Unlock()
		return nil
	}

	// The open runs under mu so Rebind, which clears the listener's interface before it closes the lanes,
	// can't miss a lane that copied the old one.
	l, err := u.dialLane(dst)
	if err != nil {
		ls.backoffLocked(dst)
		level := ls.logLevelLocked(slog.LevelWarn)
		ls.mu.Unlock()
		u.l.Log(context.Background(), level, "lanes: open failed, staying on the listener", "udpAddr", dst, "error", err)
		return nil
	}
	next := make(map[netip.AddrPort]*lane, 1)
	if t != nil {
		for k, v := range *t {
			next[k] = v
		}
	}
	next[dst] = l
	ls.table.Store(&next)
	go u.readLane(l)
	level := ls.logLevelLocked(slog.LevelInfo)
	ls.mu.Unlock()
	u.l.Log(context.Background(), level, "lanes: opened", "udpAddr", dst, "local", l.conn.LocalAddr(), "open", len(next))
	return l
}

// dialLane opens a socket on the listener's port with SO_REUSEPORT, bound to the configured listen.host or,
// for a wildcard listener, to the source address the route to dst picks, and connected to dst. It carries
// the listener's IP_BOUND_IF, so both route the same way.
func (u *StdConn) dialLane(dst netip.AddrPort) (*lane, error) {
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()))
	network := "udp6"
	if raddr.IP.To4() != nil {
		network = "udp4"
	}
	ifindex := u.boundIf()
	local := &net.UDPAddr{IP: u.listenHost.AsSlice(), Zone: u.listenHost.Zone()}
	if u.listenHost.IsUnspecified() {
		// A connected socket gets the source address xnu would pick for an unconnected send to dst.
		d := net.Dialer{Control: laneControl(false, ifindex)}
		p, err := d.Dial(network, raddr.String())
		if err != nil {
			return nil, err
		}
		local = p.LocalAddr().(*net.UDPAddr)
		_ = p.Close()
	}
	local.Port = int(u.port)
	d := net.Dialer{LocalAddr: local, Control: laneControl(true, ifindex)}
	c, err := d.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UDPConn)
	rc, err := uc.SyscallConn()
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	l := &lane{dst: dst, conn: uc, rc: rc, send: writeFd}
	l.used.Store(monoNow())
	return l, nil
}

// laneControl sets SO_REUSEPORT when reuse is set, and IP_BOUND_IF or IPV6_BOUND_IF when ifindex isn't 0,
// before the socket binds.
func laneControl(reuse bool, ifindex int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if reuse {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if serr == nil && ifindex != 0 {
				if network == "udp4" {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifindex)
				} else {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifindex)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// boundIf returns the interface index the listener is scoped to, or 0.
func (u *StdConn) boundIf() int {
	level, opt := unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	if u.isV4 {
		level, opt = unix.IPPROTO_IP, unix.IP_BOUND_IF
	}
	v, err := unix.GetsockoptInt(int(u.sysFd), level, opt)
	if err != nil {
		return 0
	}
	return v
}

func writeFd(fd int, b []byte) error {
	_, err := syscall.Write(fd, b)
	return err
}

func (ls *lanes) backoffLocked(dst netip.AddrPort) {
	if ls.backoff == nil {
		ls.backoff = map[netip.AddrPort]time.Time{}
	}
	ls.backoff[dst] = time.Now().Add(ls.cfg.backoff)
}

// releaseLane closes l if it is still open. With backoff set, the peer stays on the listener until the
// backoff runs out. Closing waits only for a write already in a syscall: a write parked on a full buffer is
// woken, and one waiting out ENOBUFS holds no reference on the descriptor.
func (u *StdConn) releaseLane(l *lane, why string, backoff bool) {
	ls := &u.lanes
	ls.mu.Lock()
	t := ls.table.Load()
	if t == nil || (*t)[l.dst] != l {
		ls.mu.Unlock()
		return
	}
	next := make(map[netip.AddrPort]*lane, len(*t))
	for k, v := range *t {
		if v != l {
			next[k] = v
		}
	}
	ls.table.Store(&next)
	if backoff {
		ls.backoffLocked(l.dst)
	}
	// Closed under mu, so a lane opened for the same peer can't meet this one's 4-tuple still bound.
	_ = l.conn.Close()
	level := ls.logLevelLocked(slog.LevelInfo)
	ls.mu.Unlock()
	u.l.Log(context.Background(), level, "lanes: released", "udpAddr", l.dst, "reason", why, "open", len(next))
}

// releaseLanes closes every lane, for a network change or shutdown. The table is read under mu, so a lane
// still opening is closed too.
func (u *StdConn) releaseLanes(why string) {
	u.lanes.mu.Lock()
	t := u.lanes.table.Load()
	u.lanes.mu.Unlock()
	if t == nil {
		return
	}
	for _, l := range *t {
		u.releaseLane(l, why, false)
	}
}

func (u *StdConn) reapLanes(done <-chan struct{}) {
	ls := &u.lanes
	idle := ls.cfg.idle
	tick := time.NewTicker(max(min(idle/4, 5*time.Second), time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		ls.pruneSends()
		ls.pruneBackoff()
		t := ls.table.Load()
		if t == nil {
			continue
		}
		now := monoNow()
		for _, l := range *t {
			if time.Duration(now-l.used.Load()) > idle {
				u.releaseLane(l, "idle", false)
			}
		}
	}
}

// laneDead reports whether a lane send or receive error means the connected path to the peer is gone, so
// its traffic belongs back on the listener. A connected UDP socket reports a peer's ICMP unreachable as
// ECONNREFUSED on its next call, which the unconnected listener never sees.
func laneDead(errno syscall.Errno) bool {
	switch errno {
	case unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.EHOSTDOWN, unix.ENETUNREACH, unix.ENETDOWN,
		unix.EADDRNOTAVAIL, unix.EPIPE, unix.ENOTCONN, unix.EDESTADDRREQ:
		return true
	}
	return false
}

// enobufsWait is how long a lane send sleeps when the interface queue is flow controlled. The kernel posts no
// wakeup when the advisory lifts, so this polls; 50us kept a gigabit link full without spinning a core in the
// 09-25 probes.
const enobufsWait = 50 * time.Microsecond

// laneWrite writes bufs on l, one datagram per write. A full socket buffer parks the caller in the netpoller
// until the socket is writable, and a flow-controlled interface makes it wait out ENOBUFS, so a busy link
// slows the tun reader instead of dropping. Once the lane has waited cfg.enobufsMax without a send going
// through, ENOBUFS drops the datagram instead, and a dropped datagram counts as sent, as the listener's
// unreported interface drops do. closed reports that the lane was closed before bufs[sent] went out; any
// other error stops the run and is returned with how many went out.
func (u *StdConn) laneWrite(l *lane, bufs [][]byte) (sent int, errno syscall.Errno, closed bool) {
	defer func() {
		if sent > 0 {
			l.used.Store(monoNow())
		}
	}()
	for sent < len(bufs) {
		var werr error
		err := l.rc.Write(func(fd uintptr) bool {
			for sent < len(bufs) {
				werr = l.send(int(fd), bufs[sent])
				switch werr {
				case nil:
					sent++
					if l.stalled.Load() != 0 {
						l.stalled.Store(0)
					}
				case syscall.EINTR:
				case syscall.EAGAIN:
					return false
				default:
					return true
				}
			}
			return true
		})
		if err != nil {
			return sent, 0, true
		}
		switch werr {
		case nil:
		case syscall.ENOBUFS:
			// The wait runs outside RawConn.Write, which holds the descriptor and would make a close wait
			// for it.
			if l.stalled.Load() < int64(u.lanes.cfg.enobufsMax) {
				start := time.Now()
				time.Sleep(enobufsWait)
				l.stalled.Add(int64(time.Since(start)))
			} else {
				u.l.Debug("lanes: interface stayed flow controlled, dropping a datagram", "udpAddr", l.dst)
				sent++
			}
		default:
			errno, _ = werr.(syscall.Errno)
			return sent, errno, false
		}
	}
	return sent, 0, false
}

// readLane delivers a lane's datagrams through the listener's reader, serialized with ListenOut, until the
// lane is closed. Any receive error closes the lane: a connected socket reports its peer's unreachables
// here, and retrying an unexpected error could spin.
func (u *StdConn) readLane(l *lane) {
	rd := u.reader.Load()
	buf := make([]byte, MTU)
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			why := err.Error()
			var errno syscall.Errno
			if errors.As(err, &errno) && laneDead(errno) {
				why = errno.Error()
			} else {
				u.l.Warn("lanes: unexpected receive error", "udpAddr", l.dst, "error", err)
			}
			u.releaseLane(l, why, true)
			return
		}
		l.used.Store(monoNow())
		u.readMu.Lock()
		rd.r(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), buf[:n:n])
		rd.flush()
		u.readMu.Unlock()
	}
}
