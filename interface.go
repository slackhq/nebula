package nebula

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
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
	"github.com/slackhq/nebula/packet"
	"github.com/slackhq/nebula/udp"
)

const (
	mtu = 9001

	inboundBatchSize      = 32
	outboundBatchSize     = 32
	batchFlushInterval    = 50 * time.Microsecond
	maxOutstandingBatches = 1028
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
	wg      sync.WaitGroup

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics

	l *logrus.Logger

	inPool  sync.Pool
	inbound []chan *packetBatch

	outPool  sync.Pool
	outbound []chan *outboundBatch

	packetBatchPool   sync.Pool
	outboundBatchPool sync.Pool
}

type packetBatch struct {
	packets []*packet.Packet
}

func newPacketBatch() *packetBatch {
	return &packetBatch{
		packets: make([]*packet.Packet, 0, inboundBatchSize),
	}
}

func (b *packetBatch) add(p *packet.Packet) {
	b.packets = append(b.packets, p)
}

func (b *packetBatch) reset() {
	for i := range b.packets {
		b.packets[i] = nil
	}
	b.packets = b.packets[:0]
}

func (f *Interface) getPacketBatch() *packetBatch {
	if v := f.packetBatchPool.Get(); v != nil {
		b := v.(*packetBatch)
		b.reset()
		return b
	}
	return newPacketBatch()
}

func (f *Interface) releasePacketBatch(b *packetBatch) {
	b.reset()
	f.packetBatchPool.Put(b)
}

type outboundBatch struct {
	payloads []*[]byte
}

func newOutboundBatch() *outboundBatch {
	return &outboundBatch{payloads: make([]*[]byte, 0, outboundBatchSize)}
}

func (b *outboundBatch) add(buf *[]byte) {
	b.payloads = append(b.payloads, buf)
}

func (b *outboundBatch) reset() {
	for i := range b.payloads {
		b.payloads[i] = nil
	}
	b.payloads = b.payloads[:0]
}

func (f *Interface) getOutboundBatch() *outboundBatch {
	if v := f.outboundBatchPool.Get(); v != nil {
		b := v.(*outboundBatch)
		b.reset()
		return b
	}
	return newOutboundBatch()
}

func (f *Interface) releaseOutboundBatch(b *outboundBatch) {
	b.reset()
	f.outboundBatchPool.Put(b)
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

		//TODO: configurable size
		inbound:  make([]chan *packetBatch, c.routines),
		outbound: make([]chan *outboundBatch, c.routines),

		l: c.l,
	}

	for i := 0; i < c.routines; i++ {
		ifce.inbound[i] = make(chan *packetBatch, maxOutstandingBatches)
		ifce.outbound[i] = make(chan *outboundBatch, maxOutstandingBatches)
	}

	ifce.inPool = sync.Pool{New: func() any {
		return packet.New()
	}}

	ifce.outPool = sync.Pool{New: func() any {
		t := make([]byte, mtu)
		return &t
	}}

	ifce.packetBatchPool = sync.Pool{New: func() any {
		return newPacketBatch()
	}}

	ifce.outboundBatchPool = sync.Pool{New: func() any {
		return newOutboundBatch()
	}}

	ifce.tryPromoteEvery.Store(c.tryPromoteEvery)
	ifce.reQueryEvery.Store(c.reQueryEvery)
	ifce.reQueryWait.Store(int64(c.reQueryWait))

	ifce.connectionManager.intf = ifce

	return ifce, nil
}

// activate creates the interface on the host. After the interface is created, any
// other services that want to bind listeners to its IP may do so successfully. However,
// the interface isn't going to process anything until run() is called.
func (f *Interface) activate() error {
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
				return err
			}
		}
		f.readers[i] = reader
	}

	if err = f.inside.Activate(); err != nil {
		f.inside.Close()
		return err
	}

	return nil
}

func (f *Interface) run(c context.Context) (func(), error) {
	for i := 0; i < f.routines; i++ {
		// Launch n queues to read packets from udp
		f.wg.Add(1)
		go f.listenOut(i)

		// Launch n queues to read packets from tun dev
		f.wg.Add(1)
		go f.listenIn(f.readers[i], i)

		// Launch n queues to read packets from tun dev
		f.wg.Add(1)
		go f.workerIn(i, c)

		// Launch n queues to read packets from tun dev
		f.wg.Add(1)
		go f.workerOut(i, c)
	}

	return f.wg.Wait, nil
}

func (f *Interface) listenOut(i int) {
	runtime.LockOSThread()
	var li udp.Conn
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}

	batch := f.getPacketBatch()
	lastFlush := time.Now()

	flush := func(force bool) {
		if len(batch.packets) == 0 {
			if force {
				f.releasePacketBatch(batch)
			}
			return
		}

		f.inbound[i] <- batch
		batch = f.getPacketBatch()
		lastFlush = time.Now()
	}

	err := li.ListenOut(func(fromUdpAddr netip.AddrPort, payload []byte) {
		p := f.inPool.Get().(*packet.Packet)
		p.Payload = p.Payload[:mtu]
		copy(p.Payload, payload)
		p.Payload = p.Payload[:len(payload)]
		p.Addr = fromUdpAddr
		batch.add(p)

		if len(batch.packets) >= inboundBatchSize || time.Since(lastFlush) >= batchFlushInterval {
			flush(false)
		}
	})

	if len(batch.packets) > 0 {
		f.inbound[i] <- batch
	} else {
		f.releasePacketBatch(batch)
	}

	if err != nil && !f.closed.Load() {
		f.l.WithError(err).Error("Error while reading packet inbound packet, closing")
		//TODO: Trigger Control to close
	}

	f.l.Debugf("underlay reader %v is done", i)
	f.wg.Done()
}

func (f *Interface) listenIn(reader io.ReadWriteCloser, i int) {
	runtime.LockOSThread()

	batch := f.getOutboundBatch()
	lastFlush := time.Now()

	flush := func(force bool) {
		if len(batch.payloads) == 0 {
			if force {
				f.releaseOutboundBatch(batch)
			}
			return
		}

		f.outbound[i] <- batch
		batch = f.getOutboundBatch()
		lastFlush = time.Now()
	}

	for {
		p := f.outPool.Get().(*[]byte)
		*p = (*p)[:mtu]
		n, err := reader.Read(*p)
		if err != nil {
			if !f.closed.Load() {
				f.l.WithError(err).Error("Error while reading outbound packet, closing")
				//TODO: Trigger Control to close
			}
			break
		}

		*p = (*p)[:n]
		batch.add(p)

		if len(batch.payloads) >= outboundBatchSize || time.Since(lastFlush) >= batchFlushInterval {
			flush(false)
		}
	}

	if len(batch.payloads) > 0 {
		f.outbound[i] <- batch
	} else {
		f.releaseOutboundBatch(batch)
	}

	f.l.Debugf("overlay reader %v is done", i)
	f.wg.Done()
}

func (f *Interface) workerIn(i int, ctx context.Context) {
	lhh := f.lightHouse.NewRequestHandler()
	conntrackCache := firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)
	fwPacket2 := &firewall.Packet{}
	nb2 := make([]byte, 12, 12)
	result2 := make([]byte, mtu)
	h := &header.H{}

	for {
		select {
		case batch := <-f.inbound[i]:
			for _, p := range batch.packets {
				f.readOutsidePackets(p.Addr, nil, result2[:0], p.Payload, h, fwPacket2, lhh, nb2, i, conntrackCache.Get(f.l))
				p.Payload = p.Payload[:mtu]
				f.inPool.Put(p)
			}
			f.releasePacketBatch(batch)
		case <-ctx.Done():
			f.wg.Done()
			return
		}
	}
}

func (f *Interface) workerOut(i int, ctx context.Context) {
	conntrackCache := firewall.NewConntrackCacheTicker(f.conntrackCacheTimeout)
	fwPacket1 := &firewall.Packet{}
	nb1 := make([]byte, 12, 12)
	result1 := make([]byte, mtu)

	for {
		select {
		case batch := <-f.outbound[i]:
			for _, data := range batch.payloads {
				f.consumeInsidePacket(*data, fwPacket1, nb1, result1, i, conntrackCache.Get(f.l))
				*data = (*data)[:mtu]
				f.outPool.Put(data)
			}
			f.releaseOutboundBatch(batch)
		case <-ctx.Done():
			f.wg.Done()
			return
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

	// Release the udp readers
	for _, u := range f.writers {
		err := u.Close()
		if err != nil {
			f.l.WithError(err).Error("Error while closing udp socket")
		}
	}

	// Release the tun readers
	for _, u := range f.readers {
		err := u.Close()
		if err != nil {
			f.l.WithError(err).Error("Error while closing tun device")
		}
	}

	return nil
}
