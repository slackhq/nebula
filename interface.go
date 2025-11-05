package nebula

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
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
	mtu                          = 9001
	defaultGSOFlushInterval      = 150 * time.Microsecond
	defaultBatchQueueDepthFactor = 4
	defaultGSOMaxSegments        = 8
	maxKernelGSOSegments         = 64
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
	EnableGSO          bool
	EnableGRO          bool
	GSOMaxSegments     int
	routines           int
	MessageMetrics     *MessageMetrics
	version            string
	relayManager       *relayManager
	punchy             *Punchy

	tryPromoteEvery uint32
	reQueryEvery    uint32
	reQueryWait     time.Duration

	ConntrackCacheTimeout time.Duration
	BatchFlushInterval    time.Duration
	BatchQueueDepth       int
	l                     *logrus.Logger
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
	batchQueueDepth       int
	enableGSO             bool
	enableGRO             bool
	gsoMaxSegments        int
	batchUDPQueueGauge    metrics.Gauge
	batchUDPFlushCounter  metrics.Counter
	batchTunQueueGauge    metrics.Gauge
	batchTunFlushCounter  metrics.Counter
	batchFlushInterval    atomic.Int64
	sendSem               chan struct{}

	writers []udp.Conn
	readers []io.ReadWriteCloser
	batches batchPipelines

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics

	l *logrus.Logger
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

	if c.GSOMaxSegments <= 0 {
		c.GSOMaxSegments = defaultGSOMaxSegments
	}
	if c.GSOMaxSegments > maxKernelGSOSegments {
		c.GSOMaxSegments = maxKernelGSOSegments
	}
	if c.BatchQueueDepth <= 0 {
		c.BatchQueueDepth = c.routines * defaultBatchQueueDepthFactor
	}
	if c.BatchFlushInterval < 0 {
		c.BatchFlushInterval = 0
	}
	if c.BatchFlushInterval == 0 && c.EnableGSO {
		c.BatchFlushInterval = defaultGSOFlushInterval
	}

	cs := c.pki.getCertState()
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
		batchQueueDepth:       c.BatchQueueDepth,
		enableGSO:             c.EnableGSO,
		enableGRO:             c.EnableGRO,
		gsoMaxSegments:        c.GSOMaxSegments,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		messageMetrics:   c.MessageMetrics,
		cachedPacketMetrics: &cachedPacketMetrics{
			sent:    metrics.GetOrRegisterCounter("hostinfo.cached_packets.sent", nil),
			dropped: metrics.GetOrRegisterCounter("hostinfo.cached_packets.dropped", nil),
		},

		l: c.l,
	}

	ifce.tryPromoteEvery.Store(c.tryPromoteEvery)
	ifce.batchUDPQueueGauge = metrics.GetOrRegisterGauge("batch.udp.queue_depth", nil)
	ifce.batchUDPFlushCounter = metrics.GetOrRegisterCounter("batch.udp.flushes", nil)
	ifce.batchTunQueueGauge = metrics.GetOrRegisterGauge("batch.tun.queue_depth", nil)
	ifce.batchTunFlushCounter = metrics.GetOrRegisterCounter("batch.tun.flushes", nil)
	ifce.batchFlushInterval.Store(int64(c.BatchFlushInterval))
	ifce.sendSem = make(chan struct{}, c.routines)
	ifce.batches.init(c.Inside, c.routines, c.BatchQueueDepth, c.GSOMaxSegments)
	ifce.reQueryEvery.Store(c.reQueryEvery)
	ifce.reQueryWait.Store(int64(c.reQueryWait))
	if c.l.Level >= logrus.DebugLevel {
		c.l.WithFields(logrus.Fields{
			"enableGSO":       c.EnableGSO,
			"enableGRO":       c.EnableGRO,
			"gsoMaxSegments":  c.GSOMaxSegments,
			"batchQueueDepth": c.BatchQueueDepth,
			"batchFlush":      c.BatchFlushInterval,
			"batching":        ifce.batches.Enabled(),
		}).Debug("initialized batch pipelines")
	}

	ifce.connectionManager.intf = ifce

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

func (f *Interface) run() {
	// Launch n queues to read packets from udp
	for i := 0; i < f.routines; i++ {
		go f.listenOut(i)
	}

	if f.l.Level >= logrus.DebugLevel {
		f.l.WithField("batching", f.batches.Enabled()).Debug("starting interface run loops")
	}

	if f.batches.Enabled() {
		for i := 0; i < f.routines; i++ {
			go f.runInsideBatchWorker(i)
			go f.runTunWriteQueue(i)
			go f.runSendQueue(i)
		}
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < f.routines; i++ {
		go f.listenIn(f.readers[i], i)
	}
}

func (f *Interface) listenOut(i int) {
	runtime.LockOSThread()

	var li udp.Conn
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}

	ctCache := firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)
	lhh := f.lightHouse.NewRequestHandler()
	plaintext := make([]byte, udp.MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	li.ListenOut(func(fromUdpAddr netip.AddrPort, payload []byte) {
		f.readOutsidePackets(fromUdpAddr, nil, plaintext[:0], payload, h, fwPacket, lhh, nb, i, ctCache.Get(f.l))
	})
}

func (f *Interface) listenIn(reader io.ReadWriteCloser, i int) {
	runtime.LockOSThread()

	if f.batches.Enabled() {
		if br, ok := reader.(overlay.BatchReader); ok {
			f.listenInBatchLocked(reader, br, i)
			return
		}
	}

	f.listenInLegacyLocked(reader, i)
}

func (f *Interface) listenInLegacyLocked(reader io.ReadWriteCloser, i int) {
	packet := make([]byte, mtu)
	out := make([]byte, mtu)
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

func (f *Interface) listenInBatchLocked(raw io.ReadWriteCloser, reader overlay.BatchReader, i int) {
	pool := f.batches.Pool()
	if pool == nil {
		f.l.Warn("batch pipeline enabled without an allocated pool; falling back to single-packet reads")
		f.listenInLegacyLocked(raw, i)
		return
	}

	for {
		packets, err := reader.ReadIntoBatch(pool)
		if err != nil {
			if errors.Is(err, os.ErrClosed) && f.closed.Load() {
				return
			}

			if isVirtioHeadroomError(err) {
				f.l.WithError(err).Warn("Batch reader fell back due to tun headroom issue")
				f.listenInLegacyLocked(raw, i)
				return
			}

			f.l.WithError(err).Error("Error while reading outbound packet batch")
			os.Exit(2)
		}

		if len(packets) == 0 {
			continue
		}

		for _, pkt := range packets {
			if pkt == nil {
				continue
			}
			if !f.batches.enqueueRx(i, pkt) {
				pkt.Release()
			}
		}
	}
}

func (f *Interface) runInsideBatchWorker(i int) {
	queue := f.batches.rxQueue(i)
	if queue == nil {
		return
	}

	out := make([]byte, mtu)
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)
	conntrackCache := firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for pkt := range queue {
		if pkt == nil {
			continue
		}
		f.consumeInsidePacket(pkt.Payload(), fwPacket, nb, out, i, conntrackCache.Get(f.l))
		pkt.Release()
	}
}

func (f *Interface) runSendQueue(i int) {
	queue := f.batches.txQueue(i)
	if queue == nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("queue", i).Debug("tx queue not initialized; batching disabled for writer")
		}
		return
	}
	writer := f.writerForIndex(i)
	if writer == nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("queue", i).Debug("no UDP writer for batch queue")
		}
		return
	}
	if f.l.Level >= logrus.DebugLevel {
		f.l.WithField("queue", i).Debug("send queue worker started")
	}
	defer func() {
		if f.l.Level >= logrus.WarnLevel {
			f.l.WithField("queue", i).Warn("send queue worker exited")
		}
	}()

	batchCap := f.batches.batchSizeHint()
	if batchCap <= 0 {
		batchCap = 1
	}
	gsoLimit := f.effectiveGSOMaxSegments()
	if gsoLimit > batchCap {
		batchCap = gsoLimit
	}
	pending := make([]queuedDatagram, 0, batchCap)
	var (
		flushTimer *time.Timer
		flushC     <-chan time.Time
	)
	dispatch := func(reason string, timerFired bool) {
		if len(pending) == 0 {
			return
		}
		batch := pending
		f.flushAndReleaseBatch(i, writer, batch, reason)
		for idx := range batch {
			batch[idx] = queuedDatagram{}
		}
		pending = pending[:0]
		if flushTimer != nil {
			if !timerFired {
				if !flushTimer.Stop() {
					select {
					case <-flushTimer.C:
					default:
					}
				}
			}
			flushTimer = nil
			flushC = nil
		}
	}
	armTimer := func() {
		delay := f.currentBatchFlushInterval()
		if delay <= 0 {
			dispatch("nogso", false)
			return
		}
		if flushTimer == nil {
			flushTimer = time.NewTimer(delay)
			flushC = flushTimer.C
		}
	}

	for {
		select {
		case d := <-queue:
			if d.packet == nil {
				continue
			}
			if f.l.Level >= logrus.DebugLevel {
				f.l.WithFields(logrus.Fields{
					"queue":       i,
					"payload_len": d.packet.Len,
					"dest":        d.addr,
				}).Debug("send queue received packet")
			}
			pending = append(pending, d)
			if gsoLimit > 0 && len(pending) >= gsoLimit {
				dispatch("gso", false)
				continue
			}
			if len(pending) >= cap(pending) {
				dispatch("cap", false)
				continue
			}
			armTimer()
			f.observeUDPQueueLen(i)
		case <-flushC:
			dispatch("timer", true)
		}
	}
}

func (f *Interface) runTunWriteQueue(i int) {
	queue := f.batches.tunQueue(i)
	if queue == nil {
		return
	}
	writer := f.batches.inside
	if writer == nil {
		return
	}
	requiredHeadroom := writer.BatchHeadroom()

	batchCap := f.batches.batchSizeHint()
	if batchCap <= 0 {
		batchCap = 1
	}
	pending := make([]*overlay.Packet, 0, batchCap)
	var (
		flushTimer *time.Timer
		flushC     <-chan time.Time
	)
	flush := func(reason string, timerFired bool) {
		if len(pending) == 0 {
			return
		}
		valid := pending[:0]
		for idx := range pending {
			if !f.ensurePacketHeadroom(&pending[idx], requiredHeadroom, i, reason) {
				pending[idx] = nil
				continue
			}
			if pending[idx] != nil {
				valid = append(valid, pending[idx])
			}
		}
		if len(valid) > 0 {
			if _, err := writer.WriteBatch(valid); err != nil {
				f.l.WithError(err).
					WithField("queue", i).
					WithField("reason", reason).
					Warn("Failed to write tun batch")
				for _, pkt := range valid {
					if pkt != nil {
						f.writePacketToTun(i, pkt)
					}
				}
			}
		}
		pending = pending[:0]
		if flushTimer != nil {
			if !timerFired {
				if !flushTimer.Stop() {
					select {
					case <-flushTimer.C:
					default:
					}
				}
			}
			flushTimer = nil
			flushC = nil
		}
	}
	armTimer := func() {
		delay := f.currentBatchFlushInterval()
		if delay <= 0 {
			return
		}
		if flushTimer == nil {
			flushTimer = time.NewTimer(delay)
			flushC = flushTimer.C
		}
	}

	for {
		select {
		case pkt := <-queue:
			if pkt == nil {
				continue
			}
			if f.ensurePacketHeadroom(&pkt, requiredHeadroom, i, "queue") {
				pending = append(pending, pkt)
			}
			if len(pending) >= cap(pending) {
				flush("cap", false)
				continue
			}
			armTimer()
			f.observeTunQueueLen(i)
		case <-flushC:
			flush("timer", true)
		}
	}
}

func (f *Interface) flushAndReleaseBatch(index int, writer udp.Conn, batch []queuedDatagram, reason string) {
	if len(batch) == 0 {
		return
	}
	f.flushDatagrams(index, writer, batch, reason)
	for idx := range batch {
		if batch[idx].packet != nil {
			batch[idx].packet.Release()
			batch[idx].packet = nil
		}
	}
	if f.batchUDPFlushCounter != nil {
		f.batchUDPFlushCounter.Inc(int64(len(batch)))
	}
}

func (f *Interface) flushDatagrams(index int, writer udp.Conn, batch []queuedDatagram, reason string) {
	if len(batch) == 0 {
		return
	}
	if f.l.Level >= logrus.DebugLevel {
		f.l.WithFields(logrus.Fields{
			"writer":  index,
			"reason":  reason,
			"pending": len(batch),
		}).Debug("udp batch flush summary")
	}
	maxSeg := f.effectiveGSOMaxSegments()
	if bw, ok := writer.(udp.BatchConn); ok {
		chunkCap := maxSeg
		if chunkCap <= 0 {
			chunkCap = len(batch)
		}
		chunk := make([]udp.Datagram, 0, chunkCap)
		var (
			currentAddr netip.AddrPort
			segments    int
		)
		flushChunk := func() {
			if len(chunk) == 0 {
				return
			}
			if f.l.Level >= logrus.DebugLevel {
				f.l.WithFields(logrus.Fields{
					"writer":        index,
					"segments":      len(chunk),
					"dest":          chunk[0].Addr,
					"reason":        reason,
					"pending_total": len(batch),
				}).Debug("flushing UDP batch")
			}
			if err := bw.WriteBatch(chunk); err != nil {
				f.l.WithError(err).
					WithField("writer", index).
					WithField("reason", reason).
					Warn("Failed to write UDP batch")
			}
			chunk = chunk[:0]
			segments = 0
		}
		for _, item := range batch {
			if item.packet == nil || !item.addr.IsValid() {
				continue
			}
			payload := item.packet.Payload()[:item.packet.Len]
			if segments == 0 {
				currentAddr = item.addr
			}
			if item.addr != currentAddr || (maxSeg > 0 && segments >= maxSeg) {
				flushChunk()
				currentAddr = item.addr
			}
			chunk = append(chunk, udp.Datagram{Payload: payload, Addr: item.addr})
			segments++
		}
		flushChunk()
		return
	}
	for _, item := range batch {
		if item.packet == nil || !item.addr.IsValid() {
			continue
		}
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithFields(logrus.Fields{
				"writer":   index,
				"reason":   reason,
				"dest":     item.addr,
				"segments": 1,
			}).Debug("flushing UDP batch")
		}
		if err := writer.WriteTo(item.packet.Payload()[:item.packet.Len], item.addr); err != nil {
			f.l.WithError(err).
				WithField("writer", index).
				WithField("udpAddr", item.addr).
				WithField("reason", reason).
				Warn("Failed to write UDP packet")
		}
	}
}

func (f *Interface) tryQueueDatagram(q int, buf []byte, addr netip.AddrPort) bool {
	if !addr.IsValid() || !f.batches.Enabled() {
		return false
	}
	pkt := f.batches.newPacket()
	if pkt == nil {
		return false
	}
	payload := pkt.Payload()
	if len(payload) < len(buf) {
		pkt.Release()
		return false
	}
	copy(payload, buf)
	pkt.Len = len(buf)
	if f.batches.enqueueTx(q, pkt, addr) {
		f.observeUDPQueueLen(q)
		return true
	}
	pkt.Release()
	return false
}

func (f *Interface) writerForIndex(i int) udp.Conn {
	if i < 0 || i >= len(f.writers) {
		return nil
	}
	return f.writers[i]
}

func (f *Interface) writeImmediate(q int, buf []byte, addr netip.AddrPort, hostinfo *HostInfo) {
	writer := f.writerForIndex(q)
	if writer == nil {
		f.l.WithField("udpAddr", addr).
			WithField("writer", q).
			Error("Failed to write outgoing packet: no writer available")
		return
	}
	if err := writer.WriteTo(buf, addr); err != nil {
		hostinfo.logger(f.l).
			WithError(err).
			WithField("udpAddr", addr).
			Error("Failed to write outgoing packet")
	}
}

func (f *Interface) tryQueuePacket(q int, pkt *overlay.Packet, addr netip.AddrPort) bool {
	if pkt == nil || !addr.IsValid() || !f.batches.Enabled() {
		return false
	}
	if f.batches.enqueueTx(q, pkt, addr) {
		f.observeUDPQueueLen(q)
		return true
	}
	return false
}

func (f *Interface) writeImmediatePacket(q int, pkt *overlay.Packet, addr netip.AddrPort, hostinfo *HostInfo) {
	if pkt == nil {
		return
	}
	writer := f.writerForIndex(q)
	if writer == nil {
		f.l.WithField("udpAddr", addr).
			WithField("writer", q).
			Error("Failed to write outgoing packet: no writer available")
		pkt.Release()
		return
	}
	if err := writer.WriteTo(pkt.Payload()[:pkt.Len], addr); err != nil {
		hostinfo.logger(f.l).
			WithError(err).
			WithField("udpAddr", addr).
			Error("Failed to write outgoing packet")
	}
	pkt.Release()
}

func (f *Interface) writePacketToTun(q int, pkt *overlay.Packet) {
	if pkt == nil {
		return
	}
	writer := f.readers[q]
	if writer == nil {
		pkt.Release()
		return
	}
	if _, err := writer.Write(pkt.Payload()[:pkt.Len]); err != nil {
		f.l.WithError(err).Error("Failed to write to tun")
	}
	pkt.Release()
}

func (f *Interface) clonePacketWithHeadroom(pkt *overlay.Packet, required int) *overlay.Packet {
	if pkt == nil {
		return nil
	}
	payload := pkt.Payload()[:pkt.Len]
	if len(payload) == 0 && required <= 0 {
		return pkt
	}

	pool := f.batches.Pool()
	if pool != nil {
		if clone := pool.Get(); clone != nil {
			if len(clone.Payload()) >= len(payload) {
				clone.Len = copy(clone.Payload(), payload)
				pkt.Release()
				return clone
			}
			clone.Release()
		}
	}

	if required < 0 {
		required = 0
	}
	buf := make([]byte, required+len(payload))
	n := copy(buf[required:], payload)
	pkt.Release()
	return &overlay.Packet{
		Buf:    buf,
		Offset: required,
		Len:    n,
	}
}

func (f *Interface) observeUDPQueueLen(i int) {
	if f.batchUDPQueueGauge == nil {
		return
	}
	f.batchUDPQueueGauge.Update(int64(f.batches.txQueueLen(i)))
}

func (f *Interface) observeTunQueueLen(i int) {
	if f.batchTunQueueGauge == nil {
		return
	}
	f.batchTunQueueGauge.Update(int64(f.batches.tunQueueLen(i)))
}

func (f *Interface) currentBatchFlushInterval() time.Duration {
	if v := f.batchFlushInterval.Load(); v > 0 {
		return time.Duration(v)
	}
	return 0
}

func (f *Interface) ensurePacketHeadroom(pkt **overlay.Packet, required int, queue int, reason string) bool {
	p := *pkt
	if p == nil {
		return false
	}
	if required <= 0 || p.Offset >= required {
		return true
	}
	clone := f.clonePacketWithHeadroom(p, required)
	if clone == nil {
		f.l.WithFields(logrus.Fields{
			"queue":  queue,
			"reason": reason,
		}).Warn("dropping packet lacking tun headroom")
		return false
	}
	*pkt = clone
	return true
}

func isVirtioHeadroomError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "headroom") || strings.Contains(msg, "virtio")
}

func (f *Interface) effectiveGSOMaxSegments() int {
	max := f.gsoMaxSegments
	if max <= 0 {
		max = defaultGSOMaxSegments
	}
	if max > maxKernelGSOSegments {
		max = maxKernelGSOSegments
	}
	if !f.enableGSO {
		return 1
	}
	return max
}

type udpOffloadConfigurator interface {
	ConfigureOffload(enableGSO, enableGRO bool, maxSegments int)
}

func (f *Interface) applyOffloadConfig(enableGSO, enableGRO bool, maxSegments int) {
	if maxSegments <= 0 {
		maxSegments = defaultGSOMaxSegments
	}
	if maxSegments > maxKernelGSOSegments {
		maxSegments = maxKernelGSOSegments
	}
	f.enableGSO = enableGSO
	f.enableGRO = enableGRO
	f.gsoMaxSegments = maxSegments
	for _, writer := range f.writers {
		if cfg, ok := writer.(udpOffloadConfigurator); ok {
			cfg.ConfigureOffload(enableGSO, enableGRO, maxSegments)
		}
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

	if c.HasChanged("listen.gso_flush_timeout") {
		d := c.GetDuration("listen.gso_flush_timeout", defaultGSOFlushInterval)
		if d < 0 {
			d = 0
		}
		f.batchFlushInterval.Store(int64(d))
		f.l.WithField("duration", d).Info("listen.gso_flush_timeout has changed")
	} else if c.HasChanged("batch.flush_interval") {
		d := c.GetDuration("batch.flush_interval", defaultGSOFlushInterval)
		if d < 0 {
			d = 0
		}
		f.batchFlushInterval.Store(int64(d))
		f.l.WithField("duration", d).Warn("batch.flush_interval is deprecated; use listen.gso_flush_timeout")
	}

	if c.HasChanged("batch.queue_depth") {
		n := c.GetInt("batch.queue_depth", f.batchQueueDepth)
		if n != f.batchQueueDepth {
			f.batchQueueDepth = n
			f.l.Warn("batch.queue_depth changes require a restart to take effect")
		}
	}

	if c.HasChanged("listen.enable_gso") || c.HasChanged("listen.enable_gro") || c.HasChanged("listen.gso_max_segments") {
		enableGSO := c.GetBool("listen.enable_gso", f.enableGSO)
		enableGRO := c.GetBool("listen.enable_gro", f.enableGRO)
		maxSeg := c.GetInt("listen.gso_max_segments", f.gsoMaxSegments)
		f.applyOffloadConfig(enableGSO, enableGRO, maxSeg)
		f.l.WithFields(logrus.Fields{
			"enableGSO":      enableGSO,
			"enableGRO":      enableGRO,
			"gsoMaxSegments": maxSeg,
		}).Info("listen GSO/GRO configuration updated")
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

	// Release the tun device
	return f.inside.Close()
}
