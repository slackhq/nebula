//go:build !e2e_testing

package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/slackhq/nebula/internal/msgx"
	"golang.org/x/sys/unix"
)

// A connected socket is a UDP socket connected to one busy peer, on the listener's port and bound to the source
// address the listener's route to that peer picks, so the peer sees the same address and port from either. A send
// on a connected socket skips the per-datagram address and MAC policy checks, and the EndpointSecurity send check
// that xprotectd can hold every unconnected sendto on, and it is the only UDP send that reports the interface
// queue's flow control, as ENOBUFS. A connected socket wins xnu's lookup for its peer's datagrams; it never sees
// anyone else's.
//
// A connected socket sets SO_REUSEPORT and binds a specific address beside a wildcard listener, which sets
// SO_REUSEPORT only for listen routines. xnu refuses a wildcard SO_REUSEPORT bind beside a holder without the
// option, and refuses another uid's bind to an address a socket holds specifically, so no other user can join the
// port while connected sockets open and close: uid nobody got EADDRINUSE on every bind against a root listener
// with connected sockets in the 09-25 probes. A connected socket is closed, never disconnected, because xnu widens
// a disconnected socket's local address to the wildcard.
//
// Only the current remote of an established tunnel may get one: Nebula names those with SetEstablishedPeer, so an
// unauthenticated sender can't earn a connected socket by drawing replies such as recv_error or handshake
// responses.
type connSock struct {
	dst  netip.AddrPort
	peer *connSockPeer
	conn *net.UDPConn
	rc   syscall.RawConn
	// used is the monotonic time in nanoseconds of the connected socket's last send or receive.
	used atomic.Int64
	// stallAt is the monotonic time of the first ENOBUFS or EAGAIN since a send last went through, or 0, and
	// dropping is set once that stall has dropped a datagram, so each stall logs its drops once.
	stallAt  atomic.Int64
	dropping atomic.Bool
	// parkMu serializes the writes that wait for a full send buffer, since the write deadline bounding each wait
	// is the descriptor's, not the writer's.
	parkMu sync.Mutex
	// sys writes bufs on the descriptor and returns how many went out: sendFd, or a stand-in for the interface in
	// tests.
	sys func(fd int, bufs [][]byte, x *sendScratch) (int, error)
}

// sendScratch is the msghdr_x array one sendmsg_x reads.
type sendScratch struct {
	hdrs [msgx.Batch]msgx.Hdr
	iovs [msgx.Batch]unix.Iovec
}

// noSendX is set once sendmsg_x is refused; connected sockets then write one datagram per syscall.
var noSendX atomic.Bool

// sendFd writes bufs on fd, a lone datagram with write and more with one sendmsg_x, which xnu runs through the stack
// as a batch on a connected socket. It returns how many went out, or none and the errno. sendmsg_x reports EAGAIN,
// ENOBUFS and EMSGSIZE only when it took nothing, and any other error without the count it took, which a connected
// socket gets only on its first datagram, as its peer's unreachable.
func sendFd(fd int, bufs [][]byte, x *sendScratch) (int, error) {
	if len(bufs) == 1 {
		if _, err := syscall.Write(fd, bufs[0]); err != nil {
			return 0, err
		}
		return 1, nil
	}
	n := min(len(bufs), msgx.Batch)
	for i, b := range bufs[:n] {
		x.iovs[i] = unix.Iovec{Base: unsafe.SliceData(b)}
		x.iovs[i].SetLen(len(b))
		x.hdrs[i] = msgx.Hdr{Iov: &x.iovs[i], Iovlen: 1}
	}
	sent, errno := msgx.Send(uintptr(fd), x.hdrs[:n])
	clear(x.iovs[:n])
	if errno != 0 {
		return 0, errno
	}
	if sent == 0 {
		return 0, syscall.EAGAIN
	}
	return sent, nil
}

// errStallSpent is a write that found the connected socket's stall budget spent, so its datagram is dropped.
var errStallSpent = errors.New("connected socket stall budget spent")

// connSockWriter carries one write through RawConn.Write. They are pooled with fn bound once, since a closure
// passed through the RawConn interface escapes and would allocate on every send.
type connSockWriter struct {
	s *connSock
	// bufs holds a copy of the datagrams' slice headers rather than the caller's slice, which would escape
	// through the pool and cost WriteTo's one-datagram array an allocation per send.
	bufs  [msgx.Batch][]byte
	nbufs int
	park  bool
	n     int
	err   error
	fn    func(fd uintptr) bool
	x     sendScratch
}

var connSockWriters = sync.Pool{New: func() any {
	w := &connSockWriter{}
	w.fn = w.write
	return w
}}

func (w *connSockWriter) write(fd uintptr) bool {
	for {
		w.n, w.err = w.s.sys(int(fd), w.bufs[:w.nbufs], &w.x)
		switch {
		case w.err == syscall.EINTR:
		case w.err == syscall.EAGAIN && w.park:
			return false
		default:
			return true
		}
	}
}

// try writes bufs on s once and returns how many went out, or none and the write's errno,
// os.ErrDeadlineExceeded, or net.ErrClosed. With park set, EAGAIN waits in the netpoller until the socket is
// writable or the write deadline passes; without it, EAGAIN is returned.
func (s *connSock) try(bufs [][]byte, park bool) (int, error) {
	w := connSockWriters.Get().(*connSockWriter)
	w.s, w.nbufs, w.park = s, copy(w.bufs[:], bufs), park
	rerr := s.rc.Write(w.fn)
	n, err := w.n, w.err
	clear(w.bufs[:w.nbufs])
	w.s, w.nbufs, w.n, w.err = nil, 0, 0, nil
	connSockWriters.Put(w)
	switch {
	case rerr == nil:
		return n, err
	case errors.Is(rerr, os.ErrDeadlineExceeded):
		return 0, os.ErrDeadlineExceeded
	default:
		return 0, net.ErrClosed
	}
}

// connSockConfig holds the knobs, which tests change.
type connSockConfig struct {
	// max is how many connected sockets the listen routines may have open at once; 0 turns connected sockets off.
	max int
	// run is how many datagrams to one destination within one window earn it a connected socket. darwin's tun
	// hands over one packet per read, so a peer's sends arrive one WriteTo or one-datagram batch at a time and
	// busyness has to be counted across calls.
	run    int
	window time.Duration
	// idle closes a connected socket after it has neither sent nor received for this long.
	idle time.Duration
	// backoff keeps a destination whose connected socket failed on the listener for this long.
	backoff time.Duration
	// openEvery is how often the open bucket earns back an open once max are spent, which bounds connected socket
	// churn however fast senders earn connected sockets and errors close them.
	openEvery time.Duration
	// enobufsMax is how long a connected socket's sends may wait out ENOBUFS without one going through before they
	// drop instead, so a suspended interface costs one write per datagram rather than stalling the tun reader.
	enobufsMax time.Duration
}

func defaultConnSockConfig() connSockConfig {
	return connSockConfig{
		max:        8,
		run:        64,
		window:     time.Second,
		idle:       30 * time.Second,
		backoff:    30 * time.Second,
		openEvery:  time.Second,
		enobufsMax: 10 * time.Millisecond,
	}
}

// connSockGroups holds the connSocks that the listen routines bound to one address share, so the limits, the
// connected sockets and Rebind cover every routine, and a peer has at most one connected socket.
var connSockGroups = struct {
	sync.Mutex
	m map[netip.AddrPort]*connSocks
}{m: map[netip.AddrPort]*connSocks{}}

// joinConnSocks returns the connSocks u shares with the other listen routines bound to la, and makes it for the
// first.
func joinConnSocks(u *StdConn, la netip.AddrPort, s Settings) *connSocks {
	g := &connSockGroups
	g.Lock()
	defer g.Unlock()
	if cs := g.m[la]; s.Multi && cs != nil {
		cs.mu.Lock()
		cs.members = append(cs.members, u)
		cs.mu.Unlock()
		return cs
	}
	cs := &connSocks{cfg: defaultConnSockConfig(), key: la, members: []*StdConn{u}, clock: monoNow, sleep: time.Sleep}
	if cs.cfg.max > 0 && !u.listenHost.IsUnspecified() && !s.Multi {
		// A connected socket on a specific listen.host binds the listener's own address, which xnu allows only when
		// both sockets set SO_REUSEPORT, and a listener with it lets another uid bind a dual-stack wildcard on the
		// port.
		cs.off.Store(true)
		u.l.Debug("connected sockets: off for a specific listen.host", "addr", s.Listen)
	}
	if s.Multi {
		g.m[la] = cs
	}
	return cs
}

type connSocks struct {
	cfg connSockConfig
	// key is the listeners' bound address, which connSockGroups files this under.
	key netip.AddrPort
	// off keeps connected sockets from opening, when the listener's address can't be shared with them.
	off atomic.Bool
	// table maps each destination that is the remote of an established tunnel, and that a connected socket could
	// reach, to its peer; it is nil when there are none, so a send with nothing to consider costs one load. Every
	// send reads it without a lock, and mu guards copying it. An open that holds mu and still finds its peer here
	// can't outlive the tunnel.
	table atomic.Pointer[map[netip.AddrPort]*connSockPeer]
	// reserved counts the connected sockets that are open, opening or closing, against cfg.max; mu guards changing it.
	reserved atomic.Int32
	mu       sync.Mutex
	closed   bool
	// members are the listen routines' listeners that share these connected sockets.
	members []*StdConn
	// pending holds each destination whose connected socket is opening or closing, and not on its peer. xnu
	// refuses to connect a 4-tuple that is still bound, so a destination in pending can't open another.
	pending map[netip.AddrPort]struct{}
	// rebinds counts Rebinds, so an open that copied the listener's interface before one is discarded.
	rebinds uint64
	// closers tracks the goroutines that close detached connected sockets.
	closers sync.WaitGroup
	// done stops the reaper; it is made when ListenOut starts the connected sockets.
	done chan struct{}
	// opens bounds connected socket opens to cfg.max at once and one per cfg.openEvery after.
	opens gcra
	// logs bounds connected socket log lines at info or warn; see connSockLogBurst.
	logs gcra
	// clock returns monotonic nanoseconds and sleep waits out ENOBUFS: monoNow and time.Sleep, or stand-ins in
	// tests.
	clock func() int64
	sleep func(time.Duration)
	// dialHook and closeHook, when set, run just before an open's dials and a close's Close, outside mu; tests
	// use them to hold an open or close in flight.
	dialHook, closeHook func(dst netip.AddrPort)
}

// connSockPeer is what connSocks keeps about an established tunnel's remote: its connected socket, how busy it is,
// and how long a failed connected socket keeps it on the listener.
type connSockPeer struct {
	sock atomic.Pointer[connSock]
	// windowMu guards start, the monotonic time the current window began, and n, the datagrams sent in it, so a
	// window's reset and its counts can't interleave with another sender's.
	windowMu sync.Mutex
	start    int64
	n        int
	// retryAt is the monotonic time before which a peer whose connected socket failed stays on the listener;
	// connSocks.mu guards it.
	retryAt int64
}

// busy counts n more datagrams to p and reports whether it has now sent cfg.run within one window. A busy peer's
// count starts over, so a peer that can't get a connected socket retries at most once per cfg.run sends.
func (p *connSockPeer) busy(now int64, n int, cfg *connSockConfig) bool {
	p.windowMu.Lock()
	defer p.windowMu.Unlock()
	if time.Duration(now-p.start) > cfg.window {
		p.start, p.n = now, 0
	}
	p.n += n
	if p.n < cfg.run {
		return false
	}
	p.n = 0
	return true
}

// connSockLogBurst and connSockLogEvery size the bucket that lets connected socket opens, closes and failures log
// at info or warn; past it they log at debug, so churn can't flood the log.
const (
	connSockLogBurst = 32
	connSockLogEvery = 10 * time.Second
)

var monoStart = time.Now()

func monoNow() int64 { return int64(time.Since(monoStart)) }

// gcra is a token bucket kept as the monotonic time it is next full (the generic cell rate algorithm), so it needs
// no refill tick.
type gcra struct{ tat int64 }

// take spends a token from a bucket of burst that earns one back per every, and reports whether there was one to
// spend.
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
func (cs *connSocks) logLevelLocked(level slog.Level) slog.Level {
	if cs.logs.take(cs.clock(), connSockLogBurst, connSockLogEvery) {
		return level
	}
	return slog.LevelDebug
}

// startConnSocks starts the idle reaper.
func (u *StdConn) startConnSocks() {
	cs := u.socks
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed || cs.done != nil || cs.cfg.max <= 0 || cs.off.Load() {
		return
	}
	cs.done = make(chan struct{})
	go u.reapConnSocks(cs.done)
}

// stopConnSocks closes every connected socket and keeps new ones from opening, once any listen routine's listener
// closes, as they do together at shutdown. It returns once their descriptors are closed.
func (u *StdConn) stopConnSocks() {
	cs := u.socks
	cs.mu.Lock()
	cs.members = slices.DeleteFunc(cs.members, func(m *StdConn) bool { return m == u })
	if !cs.closed {
		cs.closed = true
		if cs.done != nil {
			close(cs.done)
		}
		u.detachAllLocked("close")
	}
	cs.mu.Unlock()
	connSockGroups.Lock()
	if connSockGroups.m[cs.key] == cs {
		delete(connSockGroups.m, cs.key)
	}
	connSockGroups.Unlock()
	cs.closers.Wait()
}

// siblings returns the other listen routines' listeners.
func (cs *connSocks) siblings(u *StdConn) []*StdConn {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(cs.members), func(m *StdConn) bool { return m == u })
}

// connSockFor returns dst's connected socket, or nil.
func (u *StdConn) connSockFor(dst netip.AddrPort) *connSock {
	if p := u.socks.peer(dst); p != nil {
		return p.sock.Load()
	}
	return nil
}

func (cs *connSocks) peer(dst netip.AddrPort) *connSockPeer {
	if t := cs.table.Load(); t != nil {
		return (*t)[dst]
	}
	return nil
}

// SetEstablishedPeer makes dst eligible for a connected socket while it is the remote of an established tunnel,
// and closes the one it has once it no longer is. Nebula calls it for every listen routine under the hostmap's
// write lock, so repeats are no-ops and it makes no syscalls: the descriptor is closed by another goroutine.
func (u *StdConn) SetEstablishedPeer(dst netip.AddrPort, established bool) {
	cs := u.socks
	if cs.cfg.max <= 0 || cs.off.Load() || !u.connSockable(dst) {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	t := cs.table.Load()
	p := cs.peer(dst)
	if cs.closed || (p != nil) == established {
		return
	}
	next := map[netip.AddrPort]*connSockPeer{}
	if t != nil {
		next = maps.Clone(*t)
	}
	if established {
		p = &connSockPeer{start: cs.clock()}
		next[dst] = p
	} else {
		delete(next, dst)
		if s := p.sock.Load(); s != nil {
			u.detachLocked(s, "tunnel gone", false)
		}
	}
	cs.storeTableLocked(next)
}

// storeTableLocked publishes t, or nil for an empty one.
func (cs *connSocks) storeTableLocked(t map[netip.AddrPort]*connSockPeer) {
	if len(t) == 0 {
		cs.table.Store(nil)
		return
	}
	cs.table.Store(&t)
}

// connSockable reports whether a connected socket to dst could send what the listener would. A v4 listener can't
// reach a v6 destination at all, and a connected socket bound to a specific listen.host must share its family.
func (u *StdConn) connSockable(dst netip.AddrPort) bool {
	if !dst.IsValid() || dst.Port() == 0 {
		return false
	}
	if u.isV4 {
		return dst.Addr().Is4()
	}
	return u.listenHost.IsUnspecified() || u.listenHost.Unmap().Is4() == dst.Addr().Unmap().Is4()
}

// connSockRun sends bufs, all to p's destination, on p's connected socket, opening one if they make p busy. It
// returns how many went out; when that is short of len(bufs), err is the failure of bufs[sent], or nil to leave
// bufs[sent:] to the listener.
func (u *StdConn) connSockRun(p *connSockPeer, dst netip.AddrPort, bufs [][]byte) (sent int, err error) {
	s := p.sock.Load()
	if s == nil {
		if s = u.maybeOpenConnSock(p, dst, len(bufs)); s == nil {
			return 0, nil
		}
	}
	sent, errno, closed := u.connSockWrite(s, bufs)
	switch {
	case sent == len(bufs):
	case connSockDead(errno):
		u.closeConnSock(s, errno.Error(), true)
	case !closed:
		return sent, &net.OpError{Op: "write", Err: errno}
	}
	return sent, nil
}

// maybeOpenConnSock counts n datagrams to p, and opens a connected socket to it once it is busy and nothing rules
// one out.
func (u *StdConn) maybeOpenConnSock(p *connSockPeer, dst netip.AddrPort, n int) *connSock {
	cs := u.socks
	if n <= 0 || !u.listening.Load() || int(cs.reserved.Load()) >= cs.cfg.max || !p.busy(cs.clock(), n, &cs.cfg) {
		return nil
	}
	cs.mu.Lock()
	if cs.closed || cs.peer(dst) != p {
		cs.mu.Unlock()
		return nil
	}
	if s := p.sock.Load(); s != nil {
		cs.mu.Unlock()
		return s
	}
	now := cs.clock()
	if _, ok := cs.pending[dst]; ok || int(cs.reserved.Load()) >= cs.cfg.max || now < p.retryAt ||
		!cs.opens.take(now, cs.cfg.max, cs.cfg.openEvery) {
		cs.mu.Unlock()
		return nil
	}
	if cs.pending == nil {
		cs.pending = map[netip.AddrPort]struct{}{}
	}
	cs.pending[dst] = struct{}{}
	cs.reserved.Add(1)
	rebinds := cs.rebinds
	cs.mu.Unlock()

	if cs.dialHook != nil {
		cs.dialHook(dst)
	}
	s, err := u.dialConnSock(p, dst)

	cs.mu.Lock()
	if err != nil {
		delete(cs.pending, dst)
		cs.reserved.Add(-1)
		p.retryAt = cs.clock() + int64(cs.cfg.backoff)
		level := cs.logLevelLocked(slog.LevelWarn)
		cs.mu.Unlock()
		u.l.Log(context.Background(), level, "connected socket: open failed, staying on the listener", "udpAddr", dst, "error", err)
		return nil
	}
	if cs.closed || cs.rebinds != rebinds || cs.peer(dst) != p {
		// The tunnel went away, or a Rebind or shutdown ran, while the socket was opening; it stays in pending until
		// it is closed.
		cs.mu.Unlock()
		u.finishClose(s)
		u.l.Debug("connected socket: discarded, its tunnel or route changed while it opened", "udpAddr", dst)
		return nil
	}
	delete(cs.pending, dst)
	p.sock.Store(s)
	go u.readConnSock(s)
	level := cs.logLevelLocked(slog.LevelInfo)
	cs.mu.Unlock()
	u.l.Log(context.Background(), level, "connected socket: opened", "udpAddr", dst, "local", s.conn.LocalAddr(), "open", cs.reserved.Load())
	return s
}

// dialConnSock opens a socket on the listener's port with SO_REUSEPORT, bound to the configured listen.host or,
// for a wildcard listener, to the source address the route to dst picks, and connected to dst. It carries the
// listener's IP_BOUND_IF, so both route the same way.
func (u *StdConn) dialConnSock(p *connSockPeer, dst netip.AddrPort) (*connSock, error) {
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()))
	network := "udp6"
	if raddr.IP.To4() != nil {
		network = "udp4"
	}
	ifindex, err := u.boundIf()
	if err != nil {
		return nil, err
	}
	local := &net.UDPAddr{IP: u.listenHost.AsSlice(), Zone: u.listenHost.Zone()}
	if u.listenHost.IsUnspecified() {
		// A connected socket gets the source address xnu would pick for an unconnected send to dst.
		d := net.Dialer{Control: connSockControl(false, ifindex)}
		probe, err := d.Dial(network, raddr.String())
		if err != nil {
			return nil, err
		}
		local = probe.LocalAddr().(*net.UDPAddr)
		_ = probe.Close()
	}
	local.Port = int(u.port)
	d := net.Dialer{LocalAddr: local, Control: connSockControl(true, ifindex)}
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
	s := &connSock{dst: dst, peer: p, conn: uc, rc: rc, sys: sendFd}
	s.used.Store(u.socks.clock())
	return s, nil
}

// connSockControl sets SO_REUSEPORT when reuse is set, and IP_BOUND_IF or IPV6_BOUND_IF when ifindex isn't 0,
// before the socket binds.
func connSockControl(reuse bool, ifindex int) func(network, address string, c syscall.RawConn) error {
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

// boundIf returns the interface index the listener is scoped to, or 0. An error keeps the peer on the listener,
// since a connected socket opened without the listener's scope could route out an interface the listener can't.
func (u *StdConn) boundIf() (int, error) {
	level, opt := unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	if u.isV4 {
		level, opt = unix.IPPROTO_IP, unix.IP_BOUND_IF
	}
	v, err := unix.GetsockoptInt(int(u.sysFd), level, opt)
	if err != nil {
		return 0, fmt.Errorf("reading the listener's bound interface: %w", err)
	}
	return v, nil
}

// closeConnSock closes s if it is still open. With backoff set, the peer stays on the listener until the backoff
// runs out.
func (u *StdConn) closeConnSock(s *connSock, why string, backoff bool) {
	u.socks.mu.Lock()
	u.detachLocked(s, why, backoff)
	u.socks.mu.Unlock()
}

// detachLocked takes s off its peer, if it is still there, and closes it on another goroutine, since callers such
// as SetEstablishedPeer hold locks that no socket syscall should run under. s.dst stays in pending until the close
// completes.
func (u *StdConn) detachLocked(s *connSock, why string, backoff bool) {
	cs := u.socks
	if !s.peer.sock.CompareAndSwap(s, nil) {
		return
	}
	if backoff {
		s.peer.retryAt = cs.clock() + int64(cs.cfg.backoff)
	}
	if cs.pending == nil {
		cs.pending = map[netip.AddrPort]struct{}{}
	}
	cs.pending[s.dst] = struct{}{}
	level := cs.logLevelLocked(slog.LevelInfo)
	cs.closers.Add(1)
	go func() {
		defer cs.closers.Done()
		open := u.finishClose(s)
		u.l.Log(context.Background(), level, "connected socket: closed", "udpAddr", s.dst, "reason", why, "open", open)
	}()
}

// finishClose closes s, whose destination is in pending, then lets the destination open again, and returns how
// many connected sockets are left. Closing waits only for a write already in a syscall: a write parked on a full
// buffer is woken, and one waiting out ENOBUFS holds no reference on the descriptor.
func (u *StdConn) finishClose(s *connSock) int32 {
	cs := u.socks
	if cs.closeHook != nil {
		cs.closeHook(s.dst)
	}
	_ = s.conn.Close()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.pending, s.dst)
	return cs.reserved.Add(-1)
}

// detachAllLocked detaches every connected socket, for a network change or shutdown.
func (u *StdConn) detachAllLocked(why string) {
	if t := u.socks.table.Load(); t != nil {
		for _, p := range *t {
			if s := p.sock.Load(); s != nil {
				u.detachLocked(s, why, false)
			}
		}
	}
}

// closeConnSocks detaches every connected socket and discards the ones still opening, for a network change.
func (u *StdConn) closeConnSocks(why string) {
	u.socks.mu.Lock()
	u.socks.rebinds++
	u.detachAllLocked(why)
	u.socks.mu.Unlock()
}

func (u *StdConn) reapConnSocks(done <-chan struct{}) {
	cs := u.socks
	idle := cs.cfg.idle
	tick := time.NewTicker(max(min(idle/4, 5*time.Second), time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		t := cs.table.Load()
		if t == nil {
			continue
		}
		now := cs.clock()
		for _, p := range *t {
			if s := p.sock.Load(); s != nil && time.Duration(now-s.used.Load()) > idle {
				u.closeConnSock(s, "idle", false)
			}
		}
	}
}

// connSockDead reports whether a connected socket send or receive error means the connected path to the peer is
// gone, so its traffic belongs back on the listener. A connected UDP socket reports a peer's ICMP unreachable as
// ECONNREFUSED on its next call, which the unconnected listener never sees.
func connSockDead(errno syscall.Errno) bool {
	switch errno {
	case unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.EHOSTDOWN, unix.ENETUNREACH, unix.ENETDOWN,
		unix.EADDRNOTAVAIL, unix.EPIPE, unix.ENOTCONN, unix.EDESTADDRREQ:
		return true
	}
	return false
}

// enobufsWait is how long a connected socket send sleeps when the interface queue is flow controlled. The kernel
// posts no wakeup when the advisory lifts, so this polls; 50us kept a gigabit link full without spinning a core in
// the 09-25 probes.
const enobufsWait = 50 * time.Microsecond

// connSockWrite writes bufs on s, up to msgx.Batch datagrams per sendmsg_x. A full socket buffer parks the caller in the netpoller
// until the socket is writable, and a flow-controlled interface makes it wait out ENOBUFS, so a busy link slows
// the tun reader instead of dropping. Once the connected socket has waited cfg.enobufsMax without a send going
// through, either one drops the datagram instead, and a dropped datagram counts as sent, as the listener's
// unreported interface drops do; it never falls back to the listener, which would reorder it. closed reports that
// the connected socket was closed before bufs[sent] went out; any other error stops the run and is returned with
// how many went out.
func (u *StdConn) connSockWrite(s *connSock, bufs [][]byte) (sent int, errno syscall.Errno, closed bool) {
	cs := u.socks
	defer func() {
		if sent > 0 {
			s.used.Store(cs.clock())
		}
	}()
	probe := false
	for sent < len(bufs) {
		n := 1
		if !noSendX.Load() && !probe {
			n = len(bufs) - sent
		}
		k, err := s.try(bufs[sent:sent+n], false)
		if errno, ok := err.(syscall.Errno); ok && n > 1 && msgx.Unsupported(errno) {
			// EPERM may be the datagram's own fault, so sendmsg_x is off for good only once a plain write of the same
			// datagram goes through.
			probe = true
			continue
		}
		if probe && err == nil && noSendX.CompareAndSwap(false, true) {
			u.l.Warn("sendmsg_x unavailable, writing one datagram per syscall")
		}
		probe = false
		if err == syscall.EAGAIN || err == os.ErrDeadlineExceeded {
			// os.ErrDeadlineExceeded here is another writer's parked deadline, passed but not yet cleared.
			k, err = u.parkedWrite(s, bufs[sent:sent+1])
		}
		switch err {
		case nil:
			sent += k
			if s.stallAt.Load() != 0 {
				s.stallAt.Store(0)
				s.dropping.Store(false)
			}
			continue
		case errStallSpent:
			u.dropStalled(s)
			sent++
			continue
		}
		errno, ok := err.(syscall.Errno)
		if !ok {
			return sent, 0, true
		}
		if errno != syscall.ENOBUFS {
			return sent, errno, false
		}
		// The wait holds no reference on the descriptor, so a close doesn't wait for it.
		if s.stalledFor(cs.clock()) < cs.cfg.enobufsMax {
			cs.sleep(enobufsWait)
		} else {
			u.dropStalled(s)
			sent++
		}
	}
	return sent, 0, false
}

// parkedWrite writes b after EAGAIN, parked in the netpoller for what is left of s's stall budget, and returns
// errStallSpent once none is. golang/go#73919: a darwin UDP write parked on EAGAIN can wait forever for a
// writability event that never comes, so the wait always has a deadline.
func (u *StdConn) parkedWrite(s *connSock, b [][]byte) (int, error) {
	cs := u.socks
	s.parkMu.Lock()
	defer s.parkMu.Unlock()
	left := cs.cfg.enobufsMax - s.stalledFor(cs.clock())
	if left <= 0 {
		return 0, errStallSpent
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(left)); err != nil {
		return 0, net.ErrClosed
	}
	n, err := s.try(b, true)
	_ = s.conn.SetWriteDeadline(time.Time{})
	if err == os.ErrDeadlineExceeded {
		return 0, errStallSpent
	}
	return n, err
}

// dropStalled logs the first datagram a stall drops.
func (u *StdConn) dropStalled(s *connSock) {
	if !s.dropping.Swap(true) {
		u.l.Debug("connected socket: sends stalled, dropping datagrams until one goes through", "udpAddr", s.dst)
	}
}

// stalledFor records an ENOBUFS or EAGAIN on s at now and returns how long its sends have stalled: since the first
// ENOBUFS or EAGAIN after a send last went through. Every writer measures from that one time, so concurrent writers
// spend the budget no faster than one, and a send going through ends the stall for every writer, including one
// asleep in it.
func (s *connSock) stalledFor(now int64) time.Duration {
	if s.stallAt.CompareAndSwap(0, now) {
		return 0
	}
	at := s.stallAt.Load()
	if at == 0 {
		return 0
	}
	return time.Duration(now - at)
}

// readConnSock hands a connected socket's batches to ListenOut until the connected socket is closed. Any receive
// error closes it: a connected socket reports its peer's unreachables here, and retrying an unexpected error could
// spin.
func (u *StdConn) readConnSock(s *connSock) {
	r := u.newBatchReader(s.conn, s.rc)
	for {
		b, err := u.read(r)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			why := err.Error()
			var errno syscall.Errno
			if errors.As(err, &errno) && connSockDead(errno) {
				why = errno.Error()
			} else {
				u.l.Warn("connected socket: unexpected receive error", "udpAddr", s.dst, "error", err)
			}
			u.closeConnSock(s, why, true)
			return
		}
		s.used.Store(u.socks.clock())
		if !u.deliver(b) {
			return
		}
	}
}
