package nebula

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/util"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/udp"
)

const mtu = 9001

type InterfaceConfig struct {
	HostMap            *HostMap
	Outside            udp.Conn
	Inside             overlay.Device
	pki                *PKI
	Cipher             string
	Firewall           *Firewall
	DnsServer          *dnsServer
	HandshakeManager   *HandshakeManager
	lightHouse         *LightHouse
	connectionManager  *connectionManager
	DropLocalBroadcast bool
	DropMulticast      bool
	routines           int
	// Multiport means writers[i] is bound to listen.port+i (not a shared
	// SO_REUSEPORT port) and lane tunnels are negotiated with capable peers.
	Multiport bool
	// LaneCount is the number of lanes counting the base tunnel as lane 0
	// (multiport.lanes, clamped to routines). Routines at or beyond it share
	// the configured lanes round-robin.
	LaneCount      int
	MessageMetrics *MessageMetrics
	version        string
	relayManager   *relayManager
	punchy         *Punchy

	tryPromoteEvery uint32
	reQueryEvery    uint32
	reQueryWait     time.Duration

	ConntrackCacheTimeout time.Duration

	// CpuAffinity, when non-empty, names the CPUs each TUN reader goroutine
	// should pin to. Queue i pins to CpuAffinity[i % len(CpuAffinity)] —
	// shorter lists than `routines` cycle. Empty list keeps the default
	// pin-to-(i % NumCPU) behavior. Only consulted when PinThreads is true.
	CpuAffinity []int
	// PinThreads controls whether each TUN reader OS thread is pinned to a
	// single CPU (via tun.pin_threads, default true). Pinning keeps each
	// goroutine's sendmmsg on one XPS-selected NIC TX ring so per-flow
	// packets stay ordered on the wire.
	PinThreads bool

	l *slog.Logger
}

type Interface struct {
	hostMap               *HostMap
	outside               udp.Conn
	inside                overlay.Device
	pki                   *PKI
	firewall              *Firewall
	connectionManager     *connectionManager
	handshakeManager      *HandshakeManager
	dnsServer             *dnsServer
	createTime            time.Time
	lightHouse            *LightHouse
	myBroadcastAddrsTable *bart.Lite
	myVpnAddrs            []netip.Addr // A list of addresses assigned to us via our certificate
	myVpnAddrsTable       *bart.Lite
	myVpnNetworks         []netip.Prefix // A list of networks assigned to us via our certificate
	myVpnNetworksTable    *bart.Lite
	dropLocalBroadcast    bool
	dropMulticast         bool
	routines              int
	multiport             bool
	laneCount             int
	disconnectInvalid     atomic.Bool
	closed                atomic.Bool
	// cpuAffinity, when non-empty, names the CPUs each TUN reader goroutine
	// should pin to. Queue i pins to cpuAffinity[i % len(cpuAffinity)].
	// Empty falls back to the default pin-to-(allowed CPU) behavior.
	// Only consulted when pinThreads is true.
	cpuAffinity []int
	// pinThreads controls whether listenIn pins each TUN reader OS thread to
	// a CPU at all (tun.pin_threads, default true). When false, threads are
	// left free to migrate as on stock nebula.
	pinThreads   bool
	relayManager *relayManager

	tryPromoteEvery atomic.Uint32
	reQueryEvery    atomic.Uint32
	reQueryWait     atomic.Int64

	sendRecvErrorConfig   recvErrorConfig
	acceptRecvErrorConfig recvErrorConfig

	// Bumped on every udp rebind, tunnels compare it to decide they need a punch from the far side
	rebindEpoch atomic.Uint32
	version     string

	conntrackCacheTimeout time.Duration

	ctx     context.Context
	writers []udp.Conn
	queues  []tio.Queue
	// batchers is one per tun queue, wrapping queues[i]. readOutsidePackets
	// commits plaintext into the batcher; the plaintext is decrypted
	// in place inside the UDP receive buffers, so listenOut must call Flush
	// at the end of each UDP recvmmsg batch, before those buffers are
	// reused (every udp.Conn ListenOut guarantees that ordering).
	batchers []*batch.MultiCoalescer
	wg       sync.WaitGroup

	// fatalErr holds the first unexpected reader error that caused shutdown.
	// nil means "no fatal error" (yet)
	fatalErr atomic.Pointer[error]
	// triggerShutdown is a function that will be run exactly once, when onFatal swaps something non-nil into fatalErr
	triggerShutdown func()

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics
	metricTxDropped     metrics.Counter

	l *slog.Logger
}

type EncWriter interface {
	SendVia(via *HostInfo, relay *Relay, ad, nb, out []byte, nocopy bool, q int)
	SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte)
	SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte)
	Handshake(vpnAddr netip.Addr)
	GetHostInfo(vpnAddr netip.Addr) *HostInfo
	GetCertState() *CertState
}

type recvErrorConfig uint8

const (
	recvErrorAlways recvErrorConfig = iota
	recvErrorNever
	recvErrorPrivate
)

func (s recvErrorConfig) ShouldRecvError(endpoint netip.AddrPort) bool {
	switch s {
	case recvErrorPrivate:
		return endpoint.Addr().IsPrivate()
	case recvErrorAlways:
		return true
	case recvErrorNever:
		return false
	default:
		panic(fmt.Errorf("invalid recvErrorConfig value: %d", s))
	}
}

func (s recvErrorConfig) String() string {
	switch s {
	case recvErrorAlways:
		return "always"
	case recvErrorNever:
		return "never"
	case recvErrorPrivate:
		return "private"
	default:
		return fmt.Sprintf("invalid(%d)", s)
	}
}

func NewInterface(ctx context.Context, c *InterfaceConfig) (*Interface, error) {
	if c.Outside == nil {
		return nil, errors.New("no outside connection")
	}
	if c.Inside == nil {
		return nil, errors.New("no inside interface (tun)")
	}
	if c.pki == nil {
		return nil, errors.New("no certificate state")
	}
	if c.Firewall == nil {
		return nil, errors.New("no firewall rules")
	}
	if c.connectionManager == nil {
		return nil, errors.New("no connection manager")
	}

	if c.routines <= 1 {
		c.PinThreads = false //pinning is not useful unless there's more than one tun reader
	}

	cs := c.pki.getCertState()
	ifce := &Interface{
		ctx:                   ctx,
		pki:                   c.pki,
		hostMap:               c.HostMap,
		outside:               c.Outside,
		inside:                c.Inside,
		firewall:              c.Firewall,
		dnsServer:             c.DnsServer,
		handshakeManager:      c.HandshakeManager,
		createTime:            time.Now(),
		lightHouse:            c.lightHouse,
		dropLocalBroadcast:    c.DropLocalBroadcast,
		dropMulticast:         c.DropMulticast,
		routines:              c.routines,
		multiport:             c.Multiport,
		laneCount:             c.LaneCount,
		version:               c.version,
		writers:               make([]udp.Conn, c.routines),
		batchers:              make([]*batch.MultiCoalescer, c.routines),
		myVpnNetworks:         cs.myVpnNetworks,
		myVpnNetworksTable:    cs.myVpnNetworksTable,
		myVpnAddrs:            cs.myVpnAddrs,
		myVpnAddrsTable:       cs.myVpnAddrsTable,
		myBroadcastAddrsTable: cs.myVpnBroadcastAddrsTable,
		relayManager:          c.relayManager,
		connectionManager:     c.connectionManager,
		conntrackCacheTimeout: c.ConntrackCacheTimeout,
		cpuAffinity:           c.CpuAffinity,
		pinThreads:            c.PinThreads,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		metricTxDropped:  metrics.GetOrRegisterCounter("udp.tx.dropped", nil),
		messageMetrics:   c.MessageMetrics,
		cachedPacketMetrics: &cachedPacketMetrics{
			sent:    metrics.GetOrRegisterCounter("hostinfo.cached_packets.sent", nil),
			dropped: metrics.GetOrRegisterCounter("hostinfo.cached_packets.dropped", nil),
		},

		l: c.l,
	}

	ifce.tryPromoteEvery.Store(c.tryPromoteEvery)
	ifce.reQueryEvery.Store(c.reQueryEvery)
	ifce.reQueryWait.Store(int64(c.reQueryWait))

	ifce.connectionManager.intf = ifce

	// Held until Close so waiting on the interface blocks until the resources are actually released
	ifce.wg.Add(1)

	return ifce, nil
}

// activate creates the interface on the host. After the interface is created, any
// other services that want to bind listeners to its IP may do so successfully. However,
// the interface isn't going to process anything until run() is called.
func (f *Interface) activate() error {
	// actually turn on tun dev

	addr, err := f.outside.LocalAddr()
	if err != nil {
		f.l.Error("Failed to get udp listen address", "error", err)
	}

	f.l.Info("Nebula interface is active",
		"interface", f.inside.Name(),
		"networks", f.myVpnNetworks,
		"build", f.version,
		"udpAddr", addr,
		"boringcrypto", boringEnabled(),
		"fips140Version", fips140.Version(),
		"fips140Enabled", fips140.Enabled(),
		"fips140Enforced", fips140.Enforced(),
	)

	// Under multiport each socket has exactly one reader on its own port, so
	// the shared-port multi-reader capability is irrelevant (and main.go
	// already hard-errored on unsupported platforms).
	if f.routines > 1 && !f.multiport && !f.outside.SupportsMultipleReaders() {
		f.routines = 1
		f.l.Warn("multiple udp readers are not supported on this platform, falling back to a single routine")
	}

	// Prepare the tun queues. A device that can't open that many hands back
	// fewer (a single queue on platforms without multiqueue support) and we
	// size the reader routines to what we actually got.
	queues, err := f.inside.Queues(f.routines)
	if err != nil {
		return err
	}
	if len(queues) < f.routines {
		if f.multiport {
			// The lane sockets are already bound one-per-routine; shrinking
			// the routine count would leave bound ports with no reader.
			return fmt.Errorf("multiport requires %d tun queues, device provided %d", f.routines, len(queues))
		}
		// TODO: this clamp is only safe because it is unreachable when the
		// udp side has multiple readers (linux Queues opens exactly n or
		// errors; every other platform already clamped routines to 1 above).
		// If a platform ever returns fewer queues than routines with
		// SO_REUSEPORT sockets already bound, the surplus sockets get no
		// listenOut and the kernel blackholes every flow it hashes to them —
		// fail loudly or close the extra sockets instead.
		f.l.Warn("tun multiqueue is not supported on this platform, falling back to fewer routines",
			"requested", f.routines, "opened", len(queues))
		f.routines = len(queues)
	}
	f.queues = queues

	metrics.GetOrRegisterGauge("routines", nil).Update(int64(f.routines))

	for i := range f.queues {
		f.batchers[i] = batch.NewMultiCoalescer(f.queues[i], f.l)
	}

	// On error the caller owns the cleanup, Control.Start cancels the service context
	// before releasing our resources so a waiter never observes a live context
	if err = f.inside.Activate(); err != nil {
		return err
	}

	return nil
}

func (f *Interface) run() {
	// Launch n queues to read packets from udp
	for i := 0; i < f.routines; i++ {
		f.wg.Go(func() {
			f.listenOut(i)
		})
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < f.routines; i++ {
		f.wg.Go(func() {
			f.listenIn(f.queues[i], i)
		})
	}

}

func (f *Interface) wait() error {
	f.wg.Wait()
	if e := f.fatalErr.Load(); e != nil {
		return *e
	}
	return nil
}

// onFatal stores the first fatal reader error, and calls triggerShutdown if it was the first one
func (f *Interface) onFatal(err error) {
	swapped := f.fatalErr.CompareAndSwap(nil, &err)
	if !swapped {
		return
	}
	if f.triggerShutdown != nil {
		f.triggerShutdown()
	}
}

type rxContext struct {
	q       int
	scratch []byte
	// nb is a re-usable nonce buffer for decrypt calls to use
	nb           []byte
	h            *header.H
	fwPacket     *firewall.ParsedPacket
	hostmapCache map[uint32]*HostInfo
	lhh          *LightHouseHandler
	ctCache      *firewall.ConntrackCacheTicker
}

func newRxContext(f *Interface, q int) *rxContext {
	return &rxContext{
		q:            q,
		scratch:      make([]byte, mtu),
		nb:           make([]byte, 12, 12),
		h:            &header.H{},
		fwPacket:     &firewall.ParsedPacket{},
		hostmapCache: map[uint32]*HostInfo{},
		lhh:          f.lightHouse.NewRequestHandler(),
		ctCache:      firewall.NewConntrackCacheTicker(f.ctx, f.l, f.conntrackCacheTimeout),
	}
}

func (f *Interface) listenOut(i int) {
	var li udp.Conn
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}

	rxc := newRxContext(f, i)

	listener := func(fromUdpAddr netip.AddrPort, payload []byte) {
		f.readOutsidePackets(ViaSender{UdpAddr: fromUdpAddr, SockIdx: i}, payload, rxc)
	}

	flusher := func() {
		if err := f.batchers[i].Flush(); err != nil {
			f.l.Error("Failed to flush tun coalescer", "error", err)
		}
		clear(rxc.hostmapCache)
	}

	err := li.ListenOut(listener, flusher)

	// An error after teardown began is shutdown noise, the closed flag covers resources
	// Close releases itself and the cancelled ctx covers ones torn down by their owners
	// reacting to it, like the user device pipes
	if err != nil && !f.closed.Load() && f.ctx.Err() == nil {
		f.l.Error("Error while reading inbound packet, closing", "error", err)
		f.onFatal(err)
	}

	f.l.Debug("underlay reader is done", "reader", i)
}

func (f *Interface) pinThisThread(i int) {
	var cpu int
	if n := len(f.cpuAffinity); n > 0 {
		// Explicit tun.cpu_affinity list wins; parseCpuAffinity already
		// validated the entries against the allowed CPU set.
		cpu = f.cpuAffinity[i%n]
	} else if allowed, err := util.AllowedCPUs(); err == nil && len(allowed) > 0 {
		// Default: spread queues across the CPUs we're actually allowed to
		// run on. Under a cpuset/taskset mask these aren't 0..NumCPU-1, so
		// i % NumCPU would pick unrunnable IDs and every pin would fail.
		cpu = allowed[i%len(allowed)]
	} else {
		cpu = i % runtime.NumCPU()
	}
	if err := util.PinThreadToCPU(cpu); err != nil {
		f.l.Warn("failed to pin tun reader to CPU", "queue", i, "cpu", cpu, "err", err)
	}
}

// txQueue is the per-routine TX state owned by one listenIn goroutine.
//
// base carries base-session data, relay carriers, and everything on a tunnel
// without lanes. It goes out the socket egressSock picks for this routine: under
// multiport that is socket 0, because base traffic must keep the base source port
// or a vanilla peer would see per-routine source ports and roam-thrash, and
// without multiport it is this routine's own socket, which shares one port with
// the rest under SO_REUSEPORT and so costs nothing to keep to itself.
// lane[s] is bound to writers[s] (listen.port+s) and carries
// traffic encrypted with lane s's session; lane[0] is base, and the rest are
// built on the first packet that picks them, since a routine that never sends on
// a lane should not hold a batch for it.
//
// Which lane a packet rides comes from its own flow hash, not from this
// routine's index. That is deliberate. Which routine reads a flow is the
// kernel's decision: it hashes the flow to a tun queue, but it also *learns*
// the queue we write that flow's inbound packets to, and prefers what it
// learned. So if the lane followed the routine, a peer whose lanes were still
// down — every peer, for the first moments of a tunnel — would write all of its
// inbound traffic to queue 0, teaching both kernels to steer every flow to
// queue 0, and every tunnel would collapse onto lane 0 and stay there for as
// long as its flows kept busy. Hashing here makes lane spread independent of
// tun steering entirely.
//
// Every batch borrows arena, so a routine holding a batch per lane still costs
// one slab. The arena is reset by flush once every batch over it is drained.
//
// Under multiport several routines therefore write to one socket, which the
// underlay serializes (see batchWriter). Per-flow wire order still holds: a flow
// is hashed onto one lane and read by one routine, so nothing else is writing it.
type txQueue struct {
	base  *batch.SendBatch
	lane  []*batch.SendBatch
	arena *batch.Arena

	// live is every batch built so far, in build order, so base is first: see
	// flush. Kept as its own slice because lane is mostly nil holes and both
	// full and flush walk this per read batch.
	live []txBatch
}

// txBatch is a live batch and the socket it writes to, which for a lane batch is
// the lane index.
type txBatch struct {
	sb   *batch.SendBatch
	sock int
}

func (f *Interface) newTxQueue(q int) *txQueue {
	baseSock := f.egressSock(q)
	arena := batch.NewArena(batch.SendBatchCap * (udp.MTU + 32))
	base := batch.NewSendBatchSharedArena(f.writers[baseSock], batch.SendBatchCap, arena)

	tx := &txQueue{
		base:  base,
		arena: arena,
		live:  []txBatch{{sb: base, sock: baseSock}},
	}
	if f.multiport && f.laneCount > 1 {
		tx.lane = make([]*batch.SendBatch, f.laneCount)
		tx.lane[0] = base
	}
	return tx
}

// laneBatch returns the batch for lane s, building it the first time this
// routine sends on that lane. Lanes this queue doesn't cover fall back to base,
// which is also lane 0's batch.
func (tx *txQueue) laneBatch(f *Interface, s int) *batch.SendBatch {
	if s <= 0 || s >= len(tx.lane) {
		return tx.base
	}
	sb := tx.lane[s]
	if sb == nil {
		sb = batch.NewSendBatchSharedArena(f.writers[s], batch.SendBatchCap, tx.arena)
		tx.lane[s] = sb
		tx.live = append(tx.live, txBatch{sb: sb, sock: s})
	}
	return sb
}

// full reports a full sendmmsg worth of work queued across every lane, rather
// than on any one of them: the arena is shared, so it is the total that bounds
// how much is outstanding.
func (tx *txQueue) full() bool {
	n := 0
	for _, b := range tx.live {
		n += b.sb.Len()
	}
	return n >= batch.SendBatchCap
}

// flush drains base before the lanes so that when a flow moves from the base
// session onto a freshly promoted lane mid-window, its packets still leave this
// host in encryption order. Resetting the shared arena is this queue's job,
// since no single batch's Flush can know the others are done with it.
func (tx *txQueue) flush(f *Interface) {
	for _, b := range tx.live {
		if b.sb.Len() > 0 {
			f.flushSendBatch(b.sb, b.sock)
		}
	}
	tx.arena.Reset()
}

func (f *Interface) listenIn(queue tio.Queue, i int) {
	// Pinning this thread (and goroutine) to a single CPU keeps every sendmmsg from this goroutine going through the
	// same TX ring on the nic, so the wire sees per-flow order. Skip entirely when tun.pin_threads is false.
	if f.pinThreads {
		f.pinThisThread(i)
	}

	rejectBuf := make([]byte, mtu)
	tx := f.newTxQueue(i)
	fwPacket := &firewall.ParsedPacket{}
	nb := make([]byte, 12, 12)

	conntrackCache := firewall.NewConntrackCacheTicker(f.ctx, f.l, f.conntrackCacheTimeout)

	for {
		pkts, err := queue.Read()
		if err != nil {
			// Same shutdown noise handling as listenOut
			if !f.closed.Load() && f.ctx.Err() == nil {
				f.l.Error("Error while reading outbound packet, closing", "error", err, "reader", i)
				f.onFatal(err)
			}
			break
		}

		for _, pkt := range pkts {
			f.consumeInsidePacket(pkt, fwPacket, nb, tx, rejectBuf, i, conntrackCache.Get())
			// Flush incrementally once a full sendmmsg batch has
			// accumulated so the first packets of a deep read drain
			// hit the wire while the rest are still being encrypted.
			if tx.full() {
				tx.flush(f)
			}
		}
		tx.flush(f)
	}

	f.l.Debug("overlay reader is done", "reader", i)
}

// flushSendBatch drains sb to the underlay and accounts for anything it could not deliver. A shortfall means
// specific destinations were undeliverable (a stale remote, a reject rule), which the backend logs per peer at
// debug; here it is only a counter, so one unreachable peer cannot spam a log line per batch.
func (f *Interface) flushSendBatch(sb *batch.SendBatch, q int) {
	queued := sb.Len()
	written, err := sb.Flush()
	if err != nil {
		f.l.Error("Failed to write outgoing batch", "error", err, "writer", q)
	}
	if dropped := queued - written; dropped > 0 {
		f.metricTxDropped.Inc(int64(dropped))
	}
}

func (f *Interface) RegisterConfigChangeCallbacks(c *config.C) {
	c.RegisterReloadCallback(f.reloadFirewall)
	c.RegisterReloadCallback(f.reloadSendRecvError)
	c.RegisterReloadCallback(f.reloadAcceptRecvError)
	c.RegisterReloadCallback(f.reloadDisconnectInvalid)
	c.RegisterReloadCallback(f.reloadMisc)

	for _, udpConn := range f.writers {
		c.RegisterReloadCallback(udpConn.ReloadConfig)
	}
}

func (f *Interface) reloadDisconnectInvalid(c *config.C) {
	initial := c.InitialLoad()
	if initial || c.HasChanged("pki.disconnect_invalid") {
		f.disconnectInvalid.Store(c.GetBool("pki.disconnect_invalid", true))
		if !initial {
			f.l.Info("pki.disconnect_invalid changed", "value", f.disconnectInvalid.Load())
		}
	}
}

func (f *Interface) reloadFirewall(c *config.C) {
	cs := f.pki.getCertState()
	curCert := cs.getCertificate(cert.Version2)
	if curCert == nil {
		curCert = cs.getCertificate(cert.Version1)
	}

	// The firewall builds its routableNetworks set from the certificate's UnsafeNetworks at construction.
	// Check to see if that set has changed, and if so, rebuild the firewall.
	certUnsafeChanged := curCert != nil && !slices.Equal(curCert.UnsafeNetworks(), f.firewall.unsafeNetworks)

	if !c.HasChanged("firewall") && !certUnsafeChanged {
		f.l.Debug("No firewall config change detected")
		return
	}

	fw, err := NewFirewallFromConfig(f.l, cs, c)
	if err != nil {
		f.l.Error("Error while creating firewall during reload", "error", err)
		return
	}

	oldFw := f.firewall
	conntrack := oldFw.Conntrack
	conntrack.Lock()
	defer conntrack.Unlock()

	fw.rulesVersion = oldFw.rulesVersion + 1
	// If rulesVersion is back to zero, we have wrapped all the way around. Be
	// safe and just reset conntrack in this case.
	if fw.rulesVersion == 0 {
		f.l.Warn("firewall rulesVersion has overflowed, resetting conntrack",
			"firewallHashes", fw.GetRuleHashes(),
			"oldFirewallHashes", oldFw.GetRuleHashes(),
			"rulesVersion", fw.rulesVersion,
		)
	} else {
		fw.Conntrack = conntrack
	}

	f.firewall = fw

	oldFw.Destroy()
	f.l.Info("New firewall has been installed",
		"firewallHashes", fw.GetRuleHashes(),
		"oldFirewallHashes", oldFw.GetRuleHashes(),
		"rulesVersion", fw.rulesVersion,
	)
}

func (f *Interface) reloadSendRecvError(c *config.C) {
	if c.InitialLoad() || c.HasChanged("listen.send_recv_error") {
		stringValue := c.GetString("listen.send_recv_error", "always")

		switch stringValue {
		case "always":
			f.sendRecvErrorConfig = recvErrorAlways
		case "never":
			f.sendRecvErrorConfig = recvErrorNever
		case "private":
			f.sendRecvErrorConfig = recvErrorPrivate
		default:
			if c.GetBool("listen.send_recv_error", true) {
				f.sendRecvErrorConfig = recvErrorAlways
			} else {
				f.sendRecvErrorConfig = recvErrorNever
			}
		}

		f.l.Info("Loaded send_recv_error config", "sendRecvError", f.sendRecvErrorConfig.String())
	}
}

func (f *Interface) reloadAcceptRecvError(c *config.C) {
	if c.InitialLoad() || c.HasChanged("listen.accept_recv_error") {
		stringValue := c.GetString("listen.accept_recv_error", "always")

		switch stringValue {
		case "always":
			f.acceptRecvErrorConfig = recvErrorAlways
		case "never":
			f.acceptRecvErrorConfig = recvErrorNever
		case "private":
			f.acceptRecvErrorConfig = recvErrorPrivate
		default:
			if c.GetBool("listen.accept_recv_error", true) {
				f.acceptRecvErrorConfig = recvErrorAlways
			} else {
				f.acceptRecvErrorConfig = recvErrorNever
			}
		}

		f.l.Info("Loaded accept_recv_error config", "acceptRecvError", f.acceptRecvErrorConfig.String())
	}
}

func (f *Interface) reloadMisc(c *config.C) {
	if c.HasChanged("counters.try_promote") {
		n := c.GetUint32("counters.try_promote", defaultPromoteEvery)
		f.tryPromoteEvery.Store(n)
		f.l.Info("counters.try_promote has changed")
	}

	if c.HasChanged("counters.requery_every_packets") {
		n := c.GetUint32("counters.requery_every_packets", defaultReQueryEvery)
		f.reQueryEvery.Store(n)
		f.l.Info("counters.requery_every_packets has changed")
	}

	if c.HasChanged("timers.requery_wait_duration") {
		n := c.GetDuration("timers.requery_wait_duration", defaultReQueryWait)
		f.reQueryWait.Store(int64(n))
		f.l.Info("timers.requery_wait_duration has changed")
	}
}

func (f *Interface) emitStats(ctx context.Context, i time.Duration) {
	ticker := time.NewTicker(i)
	defer ticker.Stop()

	udpStats := udp.NewUDPStatsEmitter(f.writers)

	certExpirationGauge := metrics.GetOrRegisterGauge("certificate.ttl_seconds", nil)
	certInitiatingVersion := metrics.GetOrRegisterGauge("certificate.initiating_version", nil)
	certMaxVersion := metrics.GetOrRegisterGauge("certificate.max_version", nil)

	// Registered only when we run multiport, so these don't sit at zero on a node
	// that was never going to have a lane and read as a broken feature.
	var lanesUpGauge, laneTunnelsGauge metrics.Gauge
	if f.multiport && f.laneCount > 1 {
		lanesUpGauge = metrics.GetOrRegisterGauge("multiport.lanes.up", nil)
		laneTunnelsGauge = metrics.GetOrRegisterGauge("multiport.lanes.tunnels", nil)
	}

	emit := func() {
		f.firewall.EmitStats()
		f.handshakeManager.EmitStats()
		udpStats()

		if lanesUpGauge != nil {
			f.emitLaneStats(lanesUpGauge, laneTunnelsGauge)
		}

		certState := f.pki.getCertState()
		defaultCrt := certState.GetDefaultCertificate()
		certExpirationGauge.Update(int64(defaultCrt.NotAfter().Sub(time.Now()) / time.Second))
		certInitiatingVersion.Update(int64(defaultCrt.Version()))

		// Report the max certificate version we are capable of using
		if certState.v2Cert != nil {
			certMaxVersion.Update(int64(certState.v2Cert.Version()))
		} else {
			certMaxVersion.Update(int64(certState.v1Cert.Version()))
		}
	}

	// Prime gauges so a Prometheus scrape that lands before the first tick
	// sees real values instead of the zero defaults (issue #907).
	emit()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit()
		}
	}
}

func (f *Interface) GetHostInfo(vpnIp netip.Addr) *HostInfo {
	return f.hostMap.QueryVpnAddr(vpnIp)
}

func (f *Interface) GetCertState() *CertState {
	return f.pki.getCertState()
}

// Close releases the interface's resources: the udp sockets and the tun device.
// It is idempotent and safe to call at any point in the lifecycle, including on an interface that never activated,
// calls after the first return nil without doing anything.
func (f *Interface) Close() error {
	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}

	var errs []error

	// Release the udp readers
	for i, u := range f.writers {
		err := u.Close()
		if err != nil {
			f.l.Error("Error while closing udp socket", "error", err, "writer", i)
			errs = append(errs, err)
		}
	}

	// Release the tun device (closing the tun also closes all readers)
	closeErr := f.inside.Close()
	if closeErr != nil {
		errs = append(errs, closeErr)
	}

	// Release the construction token so waiters know the resources are gone
	f.wg.Done()
	return errors.Join(errs...)
}
