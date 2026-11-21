package udp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/config"
)

// The TCP transport carries the same encrypted nebula packets as UDP over a stream, each prefixed with its length
// as a big endian uint16. It exists for networks that block UDP. Packets are not re-encrypted, a TCP peer is just
// another underlay address to the rest of nebula.

const (
	tcpFrameHeader     = 2
	tcpSmallFrame      = 128
	tcpSendQueue       = 1024
	tcpDialTimeout     = 5 * time.Second
	tcpWriteTimeout    = 10 * time.Second
	tcpDialRetry       = time.Second
	tcpResolveInterval = 30 * time.Second
	tcpReaderTimeout   = 5 * time.Second
	// tcpMaxConnsPerIP stops one source from taking every inbound slot
	tcpMaxConnsPerIP = 16

	defaultTCPMaxConns    = 1024
	defaultTCPIdleTimeout = 5 * time.Minute
)

var ErrTCPQueueFull = errors.New("tcp send queue full")

// TCPTransport owns the TCP listener and every TCP connection. Wrap shares it across the udp.Conn for each routine,
// a write to an address with a TCP connection (or listed in tcp.remotes) goes over TCP, everything else over UDP.
type TCPTransport struct {
	l      *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	ln     net.Listener

	maxConns     int
	idleTimeout  time.Duration
	writeTimeout time.Duration

	// peers and remotes are copy on write so the per packet lookup is lock free, peersMu serializes writers
	peers      atomic.Pointer[map[netip.AddrPort]*tcpPeer]
	remotes    atomic.Pointer[map[netip.AddrPort]struct{}]
	peersMu    sync.Mutex
	dialFailed map[netip.AddrPort]time.Time
	inbound    int
	inboundIPs map[netip.Addr]int

	// remotesMu guards rawRemotes, remotesGen and resolved, the last good addresses of each tcp.remotes entry
	remotesMu  sync.Mutex
	rawRemotes []string
	remotesGen uint64
	resolved   map[string][]netip.AddrPort

	// deliverMu serializes TCP deliveries with the primary UDP reader, they share its EncReader state
	deliverMu sync.Mutex
	recv      EncReader
	flush     func()
	ready     chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	readers   sync.WaitGroup

	// Queued frames come from two size classes so small packets, like unauthenticated recv_error replies, do not pin
	// MTU sized buffers
	smallPool sync.Pool
	largePool sync.Pool
}

type tcpPeer struct {
	t       *TCPTransport
	addr    netip.AddrPort
	inbound bool
	queue   chan *[]byte
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	conn    net.Conn
}

// NewTCPTransportFromConfig returns nil when TCP is not configured. listen is the bound UDP address, the TCP
// listener uses the same host and port.
func NewTCPTransportFromConfig(l *slog.Logger, c *config.C, listen netip.AddrPort) (*TCPTransport, error) {
	doListen := c.GetBool("tcp.listen", false)
	remotes := c.GetStringSlice("tcp.remotes", nil)
	if !doListen && len(remotes) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &TCPTransport{
		l:            l,
		ctx:          ctx,
		cancel:       cancel,
		maxConns:     c.GetInt("tcp.max_conns", defaultTCPMaxConns),
		idleTimeout:  c.GetDuration("tcp.idle_timeout", defaultTCPIdleTimeout),
		writeTimeout: tcpWriteTimeout,
		dialFailed:   map[netip.AddrPort]time.Time{},
		inboundIPs:   map[netip.Addr]int{},
		resolved:     map[string][]netip.AddrPort{},
		ready:        make(chan struct{}),
		smallPool: sync.Pool{New: func() any {
			b := make([]byte, 0, tcpFrameHeader+tcpSmallFrame)
			return &b
		}},
		largePool: sync.Pool{New: func() any {
			b := make([]byte, 0, tcpFrameHeader+MTU)
			return &b
		}},
	}
	empty := map[netip.AddrPort]*tcpPeer{}
	t.peers.Store(&empty)
	emptyRemotes := map[netip.AddrPort]struct{}{}
	t.remotes.Store(&emptyRemotes)

	if doListen {
		ln, err := net.Listen("tcp", listen.String())
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to open tcp listener: %w", err)
		}
		t.ln = ln
		l.Info("listening", "addr", ln.Addr(), "proto", "tcp")
	}

	t.setRemotes(remotes)
	go t.resolveLoop()
	return t, nil
}

// Wrap returns conns with TCP layered on, conns[0] delivers inbound TCP packets.
func (t *TCPTransport) Wrap(conns []Conn) []Conn {
	out := make([]Conn, len(conns))
	for i, c := range conns {
		out[i] = &tcpMuxConn{Conn: c, t: t, primary: i == 0}
	}
	return out
}

func (t *TCPTransport) start(r EncReader, flush func()) {
	t.startOnce.Do(func() {
		t.recv = r
		t.flush = flush
		close(t.ready)
		if t.ln != nil {
			go t.acceptLoop()
		}
	})
}

func (t *TCPTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		// Under peersMu so acceptLoop either sees the cancel or adds its peer before the snapshot
		t.peersMu.Lock()
		t.cancel()
		peers := *t.peers.Load()
		t.peersMu.Unlock()
		if t.ln != nil {
			err = t.ln.Close()
		}
		for _, p := range peers {
			p.close()
		}

		// Readers call into the interface, they must be gone before it releases the tun and udp fds
		done := make(chan struct{})
		go func() {
			t.readers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(tcpReaderTimeout):
			t.l.Warn("tcp readers did not stop", "timeout", tcpReaderTimeout)
		}
	})
	return err
}

func (t *TCPTransport) peer(addr netip.AddrPort) *tcpPeer {
	m := *t.peers.Load()
	if len(m) == 0 {
		return nil
	}
	return m[addr]
}

func (t *TCPTransport) isRemote(addr netip.AddrPort) bool {
	m := *t.remotes.Load()
	if len(m) == 0 {
		return false
	}
	_, ok := m[addr]
	return ok
}

// route returns the peer to send addr's packets to, dialing a configured remote if needed, or nil to use UDP.
func (t *TCPTransport) route(addr netip.AddrPort) *tcpPeer {
	if p := t.peer(addr); p != nil {
		return p
	}
	if !t.isRemote(addr) {
		return nil
	}
	return t.dial(addr)
}

func (t *TCPTransport) dial(addr netip.AddrPort) *tcpPeer {
	t.peersMu.Lock()
	defer t.peersMu.Unlock()
	if t.ctx.Err() != nil {
		return nil
	}
	if p := (*t.peers.Load())[addr]; p != nil {
		return p
	}
	if f, ok := t.dialFailed[addr]; ok && time.Since(f) < tcpDialRetry {
		// Still a TCP remote, dropping beats leaking the packet over UDP
		return &tcpPeer{done: closedChan}
	}
	p := t.newPeer(addr, nil, false)
	t.addPeerLocked(p)
	t.goRun(p)
	return p
}

var closedChan = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

func (t *TCPTransport) newPeer(addr netip.AddrPort, conn net.Conn, inbound bool) *tcpPeer {
	return &tcpPeer{
		t:       t,
		addr:    addr,
		inbound: inbound,
		conn:    conn,
		queue:   make(chan *[]byte, tcpSendQueue),
		done:    make(chan struct{}),
	}
}

func (t *TCPTransport) addPeerLocked(p *tcpPeer) {
	old := *t.peers.Load()
	m := make(map[netip.AddrPort]*tcpPeer, len(old)+1)
	for k, v := range old {
		m[k] = v
	}
	if prev := m[p.addr]; prev != nil {
		// A new connection from the same address replaces the old one
		go prev.close()
	}
	m[p.addr] = p
	t.peers.Store(&m)
}

func (t *TCPTransport) removePeer(p *tcpPeer) {
	t.peersMu.Lock()
	defer t.peersMu.Unlock()
	if p.inbound {
		t.inbound--
		if t.inboundIPs[p.addr.Addr()]--; t.inboundIPs[p.addr.Addr()] <= 0 {
			delete(t.inboundIPs, p.addr.Addr())
		}
	}
	old := *t.peers.Load()
	if old[p.addr] != p {
		return
	}
	m := make(map[netip.AddrPort]*tcpPeer, len(old))
	for k, v := range old {
		if k != p.addr {
			m[k] = v
		}
	}
	t.peers.Store(&m)
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			t.l.Warn("tcp accept failed", "error", err)
			select {
			case <-time.After(100 * time.Millisecond):
			case <-t.ctx.Done():
				return
			}
			continue
		}

		addr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			_ = conn.Close()
			continue
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())

		t.peersMu.Lock()
		if t.ctx.Err() != nil || t.inbound >= t.maxConns || t.inboundIPs[addr.Addr()] >= tcpMaxConnsPerIP {
			inbound := t.inbound
			t.peersMu.Unlock()
			t.l.Debug("rejecting tcp connection", "remote", addr, "inbound", inbound)
			_ = conn.Close()
			continue
		}
		t.inbound++
		t.inboundIPs[addr.Addr()]++
		p := t.newPeer(addr, conn, true)
		t.addPeerLocked(p)
		t.peersMu.Unlock()

		t.l.Debug("accepted tcp connection", "remote", addr)
		t.goRun(p)
	}
}

// deliver hands a packet to the primary reader, serialized with its UDP packets
func (t *TCPTransport) deliver(addr netip.AddrPort, b []byte) {
	t.deliverMu.Lock()
	defer t.deliverMu.Unlock()
	if t.ctx.Err() != nil {
		return
	}
	t.recv(addr, b)
	t.flush()
}

func (t *TCPTransport) goRun(p *tcpPeer) {
	t.readers.Add(1)
	go func() {
		defer t.readers.Done()
		p.run()
	}()
}

func (t *TCPTransport) getBuf(n int) *[]byte {
	if n <= tcpSmallFrame {
		return t.smallPool.Get().(*[]byte)
	}
	return t.largePool.Get().(*[]byte)
}

func (t *TCPTransport) putBuf(b *[]byte) {
	*b = (*b)[:0]
	if cap(*b) < tcpFrameHeader+MTU {
		t.smallPool.Put(b)
		return
	}
	t.largePool.Put(b)
}

// Rebind drops dialed connections, the old route is likely gone after a network change
func (t *TCPTransport) Rebind() {
	for _, p := range *t.peers.Load() {
		if !p.inbound {
			p.close()
		}
	}
}

func (t *TCPTransport) ReloadConfig(c *config.C) {
	if c.HasChanged("tcp.remotes") {
		t.setRemotes(c.GetStringSlice("tcp.remotes", nil))
	}
}

// setRemotes applies tcp.remotes. IP literals apply right away, hostnames resolve in the background so startup and
// reloads never wait on DNS.
func (t *TCPTransport) setRemotes(raw []string) {
	t.remotesMu.Lock()
	t.rawRemotes = raw
	t.remotesGen++
	prev := t.resolved
	t.resolved = map[string][]netip.AddrPort{}
	for _, r := range raw {
		addrs, err := t.resolveRemote(r, false)
		if err != nil {
			t.l.Warn("invalid tcp.remotes entry", "remote", r, "error", err)
			continue
		}
		if addrs == nil {
			addrs = prev[r]
		}
		t.resolved[r] = addrs
	}
	t.publishRemotesLocked()
	t.remotesMu.Unlock()
	t.lookupRemotes()
}

// lookupRemotes resolves each hostname independently, so a slow one does not hold up the rest. A hostname that fails
// to resolve keeps its last addresses.
func (t *TCPTransport) lookupRemotes() {
	t.remotesMu.Lock()
	raw, gen := t.rawRemotes, t.remotesGen
	t.remotesMu.Unlock()
	for _, r := range raw {
		if addrs, err := t.resolveRemote(r, false); err != nil || addrs != nil {
			continue
		}
		go func() {
			addrs, err := t.resolveRemote(r, true)
			if err != nil {
				t.l.Warn("failed to resolve tcp.remotes entry", "remote", r, "error", err)
				return
			}
			t.remotesMu.Lock()
			defer t.remotesMu.Unlock()
			if t.remotesGen != gen {
				return
			}
			t.resolved[r] = addrs
			t.publishRemotesLocked()
		}()
	}
}

func (t *TCPTransport) publishRemotesLocked() {
	m := map[netip.AddrPort]struct{}{}
	for _, addrs := range t.resolved {
		for _, a := range addrs {
			m[a] = struct{}{}
		}
	}
	t.remotes.Store(&m)
}

// resolveRemote parses a tcp.remotes entry. Without lookup a hostname returns nil.
func (t *TCPTransport) resolveRemote(r string, lookup bool) ([]netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(r)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}, nil
	}
	if !lookup {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(t.ctx, tcpDialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.AddrPort, len(ips))
	for i, ip := range ips {
		addrs[i] = netip.AddrPortFrom(ip.Unmap(), uint16(port))
	}
	return addrs, nil
}

func (t *TCPTransport) resolveLoop() {
	tick := time.NewTicker(tcpResolveInterval)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
		}
		t.lookupRemotes()
	}
}

// send queues b, it never blocks the caller on the network
func (p *tcpPeer) send(b []byte) error {
	if len(b) > MTU {
		return fmt.Errorf("packet too large for tcp: %d", len(b))
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	buf := p.t.getBuf(len(b))
	*buf = binary.BigEndian.AppendUint16(*buf, uint16(len(b)))
	*buf = append(*buf, b...)
	select {
	case p.queue <- buf:
		return nil
	default:
		p.t.putBuf(buf)
		return ErrTCPQueueFull
	}
}

func (p *tcpPeer) close() {
	p.once.Do(func() {
		close(p.done)
		p.mu.Lock()
		if p.conn != nil {
			_ = p.conn.Close()
		}
		p.mu.Unlock()
		if p.t != nil {
			p.t.removePeer(p)
		}
	})
}

func (p *tcpPeer) run() {
	defer p.close()

	if p.conn == nil {
		d := net.Dialer{Timeout: tcpDialTimeout}
		conn, err := d.DialContext(p.t.ctx, "tcp", p.addr.String())
		if err != nil {
			p.t.l.Info("tcp dial failed", "remote", p.addr, "error", err)
			p.t.peersMu.Lock()
			p.t.dialFailed[p.addr] = time.Now()
			p.t.peersMu.Unlock()
			return
		}
		p.t.peersMu.Lock()
		delete(p.t.dialFailed, p.addr)
		p.t.peersMu.Unlock()

		p.mu.Lock()
		select {
		case <-p.done:
			p.mu.Unlock()
			_ = conn.Close()
			return
		default:
		}
		p.conn = conn
		p.mu.Unlock()
		p.t.l.Info("tcp connection established", "remote", p.addr)
	}

	if tc, ok := p.conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	go p.writeLoop()
	p.readLoop()
}

func (p *tcpPeer) readLoop() {
	select {
	case <-p.t.ready:
	case <-p.done:
		return
	}

	br := bufio.NewReaderSize(p.conn, 64*1024)
	var hdr [tcpFrameHeader]byte
	buf := make([]byte, MTU)
	for {
		if p.t.idleTimeout > 0 {
			_ = p.conn.SetReadDeadline(time.Now().Add(p.t.idleTimeout))
		}
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			p.logClose(err)
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > MTU {
			p.t.l.Info("closing tcp connection, invalid frame length", "remote", p.addr, "length", n)
			return
		}
		if _, err := io.ReadFull(br, buf[:n]); err != nil {
			p.logClose(err)
			return
		}
		// The bufio buffer can outlive a close, stop delivering the moment the peer is closed
		select {
		case <-p.done:
			return
		default:
		}
		p.t.deliver(p.addr, buf[:n:n])
	}
}

func (p *tcpPeer) logClose(err error) {
	select {
	case <-p.done:
		return
	default:
	}
	if errors.Is(err, io.EOF) {
		p.t.l.Debug("tcp connection closed", "remote", p.addr)
		return
	}
	p.t.l.Info("tcp connection closed", "remote", p.addr, "error", err)
}

func (p *tcpPeer) writeLoop() {
	defer p.close()
	bw := bufio.NewWriterSize(deadlineWriter{p.conn, p.t.writeTimeout}, 64*1024)
	for {
		var buf *[]byte
		select {
		case <-p.done:
			return
		case buf = <-p.queue:
		}

		for buf != nil {
			_, err := bw.Write(*buf)
			p.t.putBuf(buf)
			if err != nil {
				p.logClose(err)
				return
			}
			select {
			case buf = <-p.queue:
			default:
				buf = nil
			}
		}
		if err := bw.Flush(); err != nil {
			p.logClose(err)
			return
		}
	}
}

// deadlineWriter bounds each write rather than a whole burst, a peer that keeps up stays connected under sustained load
type deadlineWriter struct {
	c       net.Conn
	timeout time.Duration
}

func (w deadlineWriter) Write(b []byte) (int, error) {
	_ = w.c.SetWriteDeadline(time.Now().Add(w.timeout))
	return w.c.Write(b)
}

func unwrapConns(conns []Conn) []Conn {
	out := make([]Conn, len(conns))
	for i, c := range conns {
		if w, ok := c.(interface{ Unwrap() Conn }); ok {
			c = w.Unwrap()
		}
		out[i] = c
	}
	return out
}

// tcpMuxConn layers the shared TCPTransport onto one routine's udp.Conn
type tcpMuxConn struct {
	Conn
	t         *TCPTransport
	primary   bool
	closeOnce sync.Once
	closeErr  error
}

// Unwrap returns the underlying UDP conn
func (c *tcpMuxConn) Unwrap() Conn {
	return c.Conn
}

func (c *tcpMuxConn) WriteTo(b []byte, addr netip.AddrPort) error {
	if p := c.t.route(addr); p != nil {
		return p.send(b)
	}
	return c.Conn.WriteTo(b, addr)
}

func (c *tcpMuxConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	first := -1
	for i, a := range addrs {
		if c.t.route(a) != nil {
			first = i
			break
		}
	}
	if first < 0 {
		return c.Conn.WriteBatch(bufs, addrs)
	}

	written := 0
	udpBufs := make([][]byte, 0, len(bufs))
	udpAddrs := make([]netip.AddrPort, 0, len(addrs))
	udpBufs = append(udpBufs, bufs[:first]...)
	udpAddrs = append(udpAddrs, addrs[:first]...)
	for i := first; i < len(bufs); i++ {
		p := c.t.route(addrs[i])
		if p == nil {
			udpBufs = append(udpBufs, bufs[i])
			udpAddrs = append(udpAddrs, addrs[i])
			continue
		}
		if p.send(bufs[i]) == nil {
			written++
		}
	}
	if len(udpBufs) == 0 {
		return written, nil
	}
	n, err := c.Conn.WriteBatch(udpBufs, udpAddrs)
	return written + n, err
}

func (c *tcpMuxConn) ListenOut(r EncReader, flush func()) error {
	if !c.primary {
		return c.Conn.ListenOut(r, flush)
	}

	// Hold deliverMu for a whole UDP batch so TCP packets land between batches, never inside one
	held := false
	defer func() {
		if held {
			c.t.deliverMu.Unlock()
		}
	}()
	lr := func(addr netip.AddrPort, payload []byte) {
		if !held {
			c.t.deliverMu.Lock()
			held = true
		}
		r(addr, payload)
	}
	lf := func() {
		flush()
		if held {
			held = false
			c.t.deliverMu.Unlock()
		}
	}

	c.t.start(r, flush)
	return c.Conn.ListenOut(lr, lf)
}

func (c *tcpMuxConn) Rebind() error {
	if c.primary {
		c.t.Rebind()
	}
	return c.Conn.Rebind()
}

func (c *tcpMuxConn) ReloadConfig(cfg *config.C, r *config.Reload) {
	c.Conn.ReloadConfig(cfg, r)
	if c.primary && r != nil {
		c.t.ReloadConfig(cfg)
	}
}

// Shutdown wakes the UDP reader, or closes the conn if it has no Shutdown
func (c *tcpMuxConn) Shutdown() error {
	if c.primary {
		_ = c.t.Close()
	}
	if s, ok := c.Conn.(interface{ Shutdown() error }); ok {
		return s.Shutdown()
	}
	return c.closeInner()
}

func (c *tcpMuxConn) Close() error {
	if c.primary {
		_ = c.t.Close()
	}
	return c.closeInner()
}

func (c *tcpMuxConn) closeInner() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}
