package nebula

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/udp"
)

const (
	mtu                        = 9001
	tunReadBufferSize          = mtu * 8
	defaultDecryptWorkerFactor = 2
	defaultInboundQueueDepth   = 1024
)

type InterfaceConfig struct {
	HostMap            *HostMap
	Outside            udp.Conn
	Inside             overlay.Device
	pki                *PKI
	Cipher             string
	Firewall           *Firewall
	ServeDns           bool
	HandshakeManager   *HandshakeManager
	lightHouse         *LightHouse
	connectionManager  *connectionManager
	DropLocalBroadcast bool
	DropMulticast      bool
	routines           int
	MessageMetrics     *MessageMetrics
	version            string
	relayManager       *relayManager
	punchy             *Punchy

	tryPromoteEvery uint32
	reQueryEvery    uint32
	reQueryWait     time.Duration

	ConntrackCacheTimeout time.Duration
	l                     *logrus.Logger
	DecryptWorkers        int
	DecryptQueueDepth     int
}

type Interface struct {
	hostMap               *HostMap
	outside               udp.Conn
	inside                overlay.Device
	pki                   *PKI
	firewall              *Firewall
	connectionManager     *connectionManager
	handshakeManager      *HandshakeManager
	serveDns              bool
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
	disconnectInvalid     atomic.Bool
	closed                atomic.Bool
	relayManager          *relayManager

	tryPromoteEvery atomic.Uint32
	reQueryEvery    atomic.Uint32
	reQueryWait     atomic.Int64

	sendRecvErrorConfig sendRecvErrorConfig

	// rebindCount is used to decide if an active tunnel should trigger a punch notification through a lighthouse
	rebindCount int8
	version     string

	conntrackCacheTimeout time.Duration

	writers []udp.Conn
	readers []io.ReadWriteCloser

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics

	l              *logrus.Logger
	ctx            context.Context
	udpListenWG    sync.WaitGroup
	inboundPool    sync.Pool
	decryptWG      sync.WaitGroup
	decryptQueues  []*inboundRing
	decryptWorkers int
	decryptStates  []decryptWorkerState
	decryptCounter atomic.Uint32
}

type inboundPacket struct {
	addr    netip.AddrPort
	payload []byte
	release func()
	queue   int
}

type decryptWorkerState struct {
	queue  *inboundRing
	notify chan struct{}
}

type decryptContext struct {
	ctTicker *firewall.ConntrackCacheTicker
	plain    []byte
	head     header.H
	fwPacket firewall.Packet
	light    *LightHouseHandler
	nebula   []byte
}

type inboundCell struct {
	seq atomic.Uint64
	pkt *inboundPacket
}

type inboundRing struct {
	mask       uint64
	cells      []inboundCell
	enqueuePos atomic.Uint64
	dequeuePos atomic.Uint64
}

func newInboundRing(capacity int) *inboundRing {
	if capacity < 2 {
		capacity = 2
	}
	size := nextPowerOfTwo(uint32(capacity))
	if size < 2 {
		size = 2
	}
	ring := &inboundRing{
		mask:  uint64(size - 1),
		cells: make([]inboundCell, size),
	}
	for i := range ring.cells {
		ring.cells[i].seq.Store(uint64(i))
	}
	return ring
}

func nextPowerOfTwo(v uint32) uint32 {
	if v == 0 {
		return 1
	}
	return 1 << (32 - bits.LeadingZeros32(v-1))
}

func (r *inboundRing) Enqueue(pkt *inboundPacket) bool {
	var cell *inboundCell
	pos := r.enqueuePos.Load()
	for {
		cell = &r.cells[pos&r.mask]
		seq := cell.seq.Load()
		diff := int64(seq) - int64(pos)
		if diff == 0 {
			if r.enqueuePos.CompareAndSwap(pos, pos+1) {
				break
			}
		} else if diff < 0 {
			return false
		} else {
			pos = r.enqueuePos.Load()
		}
	}
	cell.pkt = pkt
	cell.seq.Store(pos + 1)
	return true
}

func (r *inboundRing) Dequeue() (*inboundPacket, bool) {
	var cell *inboundCell
	pos := r.dequeuePos.Load()
	for {
		cell = &r.cells[pos&r.mask]
		seq := cell.seq.Load()
		diff := int64(seq) - int64(pos+1)
		if diff == 0 {
			if r.dequeuePos.CompareAndSwap(pos, pos+1) {
				break
			}
		} else if diff < 0 {
			return nil, false
		} else {
			pos = r.dequeuePos.Load()
		}
	}
	pkt := cell.pkt
	cell.pkt = nil
	cell.seq.Store(pos + r.mask + 1)
	return pkt, true
}

func (f *Interface) getInboundPacket() *inboundPacket {
	if pkt, ok := f.inboundPool.Get().(*inboundPacket); ok && pkt != nil {
		return pkt
	}
	return &inboundPacket{}
}

func (f *Interface) putInboundPacket(pkt *inboundPacket) {
	if pkt == nil {
		return
	}
	pkt.addr = netip.AddrPort{}
	pkt.payload = nil
	pkt.release = nil
	pkt.queue = 0
	f.inboundPool.Put(pkt)
}

func newDecryptContext(f *Interface) *decryptContext {
	return &decryptContext{
		ctTicker: firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout),
		plain:    make([]byte, udp.MTU),
		head:     header.H{},
		fwPacket: firewall.Packet{},
		light:    f.lightHouse.NewRequestHandler(),
		nebula:   make([]byte, 12, 12),
	}
}

func (f *Interface) processInboundPacket(pkt *inboundPacket, ctx *decryptContext) {
	if pkt == nil {
		return
	}
	defer func() {
		if pkt.release != nil {
			pkt.release()
		}
		f.putInboundPacket(pkt)
	}()

	ctx.head = header.H{}
	ctx.fwPacket = firewall.Packet{}
	var cache firewall.ConntrackCache
	if ctx.ctTicker != nil {
		cache = ctx.ctTicker.Get(f.l)
	}
	f.readOutsidePackets(pkt.addr, nil, ctx.plain[:0], pkt.payload, &ctx.head, &ctx.fwPacket, ctx.light, ctx.nebula, pkt.queue, cache)
}

type EncWriter interface {
	SendVia(via *HostInfo,
		relay *Relay,
		ad,
		nb,
		out []byte,
		nocopy bool,
	)
	SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte)
	SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte)
	Handshake(vpnAddr netip.Addr)
	GetHostInfo(vpnAddr netip.Addr) *HostInfo
	GetCertState() *CertState
}

type sendRecvErrorConfig uint8

const (
	sendRecvErrorAlways sendRecvErrorConfig = iota
	sendRecvErrorNever
	sendRecvErrorPrivate
)

func (s sendRecvErrorConfig) ShouldSendRecvError(endpoint netip.AddrPort) bool {
	switch s {
	case sendRecvErrorPrivate:
		return endpoint.Addr().IsPrivate()
	case sendRecvErrorAlways:
		return true
	case sendRecvErrorNever:
		return false
	default:
		panic(fmt.Errorf("invalid sendRecvErrorConfig value: %d", s))
	}
}

func (s sendRecvErrorConfig) String() string {
	switch s {
	case sendRecvErrorAlways:
		return "always"
	case sendRecvErrorNever:
		return "never"
	case sendRecvErrorPrivate:
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

	cs := c.pki.getCertState()
	decryptWorkers := c.DecryptWorkers
	if decryptWorkers < 0 {
		decryptWorkers = 0
	}
	if decryptWorkers == 0 {
		decryptWorkers = c.routines * defaultDecryptWorkerFactor
		if decryptWorkers < c.routines {
			decryptWorkers = c.routines
		}
	}
	if decryptWorkers < 0 {
		decryptWorkers = 0
	}
	if runtime.GOOS != "linux" {
		decryptWorkers = 0
	}

	queueDepth := c.DecryptQueueDepth
	if queueDepth <= 0 {
		queueDepth = defaultInboundQueueDepth
	}
	minDepth := c.routines * 64
	if minDepth <= 0 {
		minDepth = 64
	}
	if queueDepth < minDepth {
		queueDepth = minDepth
	}

	ifce := &Interface{
		pki:                   c.pki,
		hostMap:               c.HostMap,
		outside:               c.Outside,
		inside:                c.Inside,
		firewall:              c.Firewall,
		serveDns:              c.ServeDns,
		handshakeManager:      c.HandshakeManager,
		createTime:            time.Now(),
		lightHouse:            c.lightHouse,
		dropLocalBroadcast:    c.DropLocalBroadcast,
		dropMulticast:         c.DropMulticast,
		routines:              c.routines,
		version:               c.version,
		writers:               make([]udp.Conn, c.routines),
		readers:               make([]io.ReadWriteCloser, c.routines),
		myVpnNetworks:         cs.myVpnNetworks,
		myVpnNetworksTable:    cs.myVpnNetworksTable,
		myVpnAddrs:            cs.myVpnAddrs,
		myVpnAddrsTable:       cs.myVpnAddrsTable,
		myBroadcastAddrsTable: cs.myVpnBroadcastAddrsTable,
		relayManager:          c.relayManager,
		connectionManager:     c.connectionManager,
		conntrackCacheTimeout: c.ConntrackCacheTimeout,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		messageMetrics:   c.MessageMetrics,
		cachedPacketMetrics: &cachedPacketMetrics{
			sent:    metrics.GetOrRegisterCounter("hostinfo.cached_packets.sent", nil),
			dropped: metrics.GetOrRegisterCounter("hostinfo.cached_packets.dropped", nil),
		},

		l:              c.l,
		ctx:            ctx,
		inboundPool:    sync.Pool{New: func() any { return &inboundPacket{} }},
		decryptWorkers: decryptWorkers,
	}

	ifce.tryPromoteEvery.Store(c.tryPromoteEvery)
	ifce.reQueryEvery.Store(c.reQueryEvery)
	ifce.reQueryWait.Store(int64(c.reQueryWait))

	ifce.connectionManager.intf = ifce

	if decryptWorkers > 0 {
		ifce.decryptQueues = make([]*inboundRing, decryptWorkers)
		ifce.decryptStates = make([]decryptWorkerState, decryptWorkers)
		for i := 0; i < decryptWorkers; i++ {
			queue := newInboundRing(queueDepth)
			ifce.decryptQueues[i] = queue
			ifce.decryptStates[i] = decryptWorkerState{
				queue:  queue,
				notify: make(chan struct{}, 1),
			}
		}
	}

	return ifce, nil
}

// activate creates the interface on the host. After the interface is created, any
// other services that want to bind listeners to its IP may do so successfully. However,
// the interface isn't going to process anything until run() is called.
func (f *Interface) activate() {
	// actually turn on tun dev

	addr, err := f.outside.LocalAddr()
	if err != nil {
		f.l.WithError(err).Error("Failed to get udp listen address")
	}

	f.l.WithField("interface", f.inside.Name()).WithField("networks", f.myVpnNetworks).
		WithField("build", f.version).WithField("udpAddr", addr).
		WithField("boringcrypto", boringEnabled()).
		Info("Nebula interface is active")

	metrics.GetOrRegisterGauge("routines", nil).Update(int64(f.routines))

	// Prepare n tun queues
	var reader io.ReadWriteCloser = f.inside
	for i := 0; i < f.routines; i++ {
		if i > 0 {
			reader, err = f.inside.NewMultiQueueReader()
			if err != nil {
				f.l.Fatal(err)
			}
		}
		f.readers[i] = reader
	}

	if err := f.inside.Activate(); err != nil {
		f.inside.Close()
		f.l.Fatal(err)
	}
}

func (f *Interface) startDecryptWorkers() {
	if f.decryptWorkers <= 0 || len(f.decryptQueues) == 0 {
		return
	}
	f.decryptWG.Add(f.decryptWorkers)
	for i := 0; i < f.decryptWorkers; i++ {
		go f.decryptWorker(i)
	}
}

func (f *Interface) decryptWorker(id int) {
	defer f.decryptWG.Done()
	if id < 0 || id >= len(f.decryptStates) {
		return
	}
	state := f.decryptStates[id]
	if state.queue == nil {
		return
	}
	ctx := newDecryptContext(f)
	for {
		for {
			pkt, ok := state.queue.Dequeue()
			if !ok {
				break
			}
			f.processInboundPacket(pkt, ctx)
		}
		if f.closed.Load() || f.ctx.Err() != nil {
			for {
				pkt, ok := state.queue.Dequeue()
				if !ok {
					return
				}
				f.processInboundPacket(pkt, ctx)
			}
		}
		select {
		case <-f.ctx.Done():
		case <-state.notify:
		}
	}
}

func (f *Interface) notifyDecryptWorker(idx int) {
	if idx < 0 || idx >= len(f.decryptStates) {
		return
	}
	state := f.decryptStates[idx]
	if state.notify == nil {
		return
	}
	select {
	case state.notify <- struct{}{}:
	default:
	}
}

func (f *Interface) run() {
	f.startDecryptWorkers()
	// Launch n queues to read packets from udp
	f.udpListenWG.Add(f.routines)
	for i := 0; i < f.routines; i++ {
		go f.listenOut(i)
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < f.routines; i++ {
		go f.listenIn(f.readers[i], i)
	}
}

func (f *Interface) listenOut(i int) {
	runtime.LockOSThread()
	defer f.udpListenWG.Done()

	var li udp.Conn
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}

	useWorkers := f.decryptWorkers > 0 && len(f.decryptQueues) > 0
	var (
		inlineTicker  *firewall.ConntrackCacheTicker
		inlineHandler *LightHouseHandler
		inlinePlain   []byte
		inlineHeader  header.H
		inlinePacket  firewall.Packet
		inlineNB      []byte
		inlineCtx     *decryptContext
	)

	if useWorkers {
		inlineCtx = newDecryptContext(f)
	} else {
		inlineTicker = firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)
		inlineHandler = f.lightHouse.NewRequestHandler()
		inlinePlain = make([]byte, udp.MTU)
		inlineNB = make([]byte, 12, 12)
	}

	li.ListenOut(func(fromUdpAddr netip.AddrPort, payload []byte, release func()) {
		if !useWorkers {
			if release != nil {
				defer release()
			}
			select {
			case <-f.ctx.Done():
				return
			default:
			}
			inlineHeader = header.H{}
			inlinePacket = firewall.Packet{}
			var cache firewall.ConntrackCache
			if inlineTicker != nil {
				cache = inlineTicker.Get(f.l)
			}
			f.readOutsidePackets(fromUdpAddr, nil, inlinePlain[:0], payload, &inlineHeader, &inlinePacket, inlineHandler, inlineNB, i, cache)
			return
		}

		if f.ctx.Err() != nil {
			if release != nil {
				release()
			}
			return
		}

		pkt := f.getInboundPacket()
		pkt.addr = fromUdpAddr
		pkt.payload = payload
		pkt.release = release
		pkt.queue = i

		queueCount := len(f.decryptQueues)
		if queueCount == 0 {
			f.processInboundPacket(pkt, inlineCtx)
			return
		}
		w := int(f.decryptCounter.Add(1)-1) % queueCount
		if w < 0 || w >= queueCount || !f.decryptQueues[w].Enqueue(pkt) {
			f.processInboundPacket(pkt, inlineCtx)
			return
		}
		f.notifyDecryptWorker(w)
	})
}

func (f *Interface) listenIn(reader io.ReadWriteCloser, i int) {
	runtime.LockOSThread()

	packet := make([]byte, tunReadBufferSize)
	out := make([]byte, tunReadBufferSize)
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	conntrackCache := firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for {
		n, err := reader.Read(packet)
		if err != nil {
			if errors.Is(err, os.ErrClosed) && f.closed.Load() {
				return
			}

			f.l.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}

		f.consumeInsidePacket(packet[:n], fwPacket, nb, out, i, conntrackCache.Get(f.l))
	}
}

func (f *Interface) RegisterConfigChangeCallbacks(c *config.C) {
	c.RegisterReloadCallback(f.reloadFirewall)
	c.RegisterReloadCallback(f.reloadSendRecvError)
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
			f.l.Infof("pki.disconnect_invalid changed to %v", f.disconnectInvalid.Load())
		}
	}
}

func (f *Interface) reloadFirewall(c *config.C) {
	//TODO: need to trigger/detect if the certificate changed too
	if c.HasChanged("firewall") == false {
		f.l.Debug("No firewall config change detected")
		return
	}

	fw, err := NewFirewallFromConfig(f.l, f.pki.getCertState(), c)
	if err != nil {
		f.l.WithError(err).Error("Error while creating firewall during reload")
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
		f.l.WithField("firewallHashes", fw.GetRuleHashes()).
			WithField("oldFirewallHashes", oldFw.GetRuleHashes()).
			WithField("rulesVersion", fw.rulesVersion).
			Warn("firewall rulesVersion has overflowed, resetting conntrack")
	} else {
		fw.Conntrack = conntrack
	}

	f.firewall = fw

	oldFw.Destroy()
	f.l.WithField("firewallHashes", fw.GetRuleHashes()).
		WithField("oldFirewallHashes", oldFw.GetRuleHashes()).
		WithField("rulesVersion", fw.rulesVersion).
		Info("New firewall has been installed")
}

func (f *Interface) reloadSendRecvError(c *config.C) {
	if c.InitialLoad() || c.HasChanged("listen.send_recv_error") {
		stringValue := c.GetString("listen.send_recv_error", "always")

		switch stringValue {
		case "always":
			f.sendRecvErrorConfig = sendRecvErrorAlways
		case "never":
			f.sendRecvErrorConfig = sendRecvErrorNever
		case "private":
			f.sendRecvErrorConfig = sendRecvErrorPrivate
		default:
			if c.GetBool("listen.send_recv_error", true) {
				f.sendRecvErrorConfig = sendRecvErrorAlways
			} else {
				f.sendRecvErrorConfig = sendRecvErrorNever
			}
		}

		f.l.WithField("sendRecvError", f.sendRecvErrorConfig.String()).
			Info("Loaded send_recv_error config")
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.firewall.EmitStats()
			f.handshakeManager.EmitStats()
			udpStats()

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
	}
}

func (f *Interface) GetHostInfo(vpnIp netip.Addr) *HostInfo {
	return f.hostMap.QueryVpnAddr(vpnIp)
}

func (f *Interface) GetCertState() *CertState {
	return f.pki.getCertState()
}

func (f *Interface) Close() error {
	f.closed.Store(true)

	for _, u := range f.writers {
		err := u.Close()
		if err != nil {
			f.l.WithError(err).Error("Error while closing udp socket")
		}
	}

	f.udpListenWG.Wait()
	if f.decryptWorkers > 0 {
		for _, state := range f.decryptStates {
			if state.notify != nil {
				select {
				case state.notify <- struct{}{}:
				default:
				}
			}
		}
		f.decryptWG.Wait()
	}

	// Release the tun device
	return f.inside.Close()
}
