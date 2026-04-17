package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/util"

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
	MessageMetrics     *MessageMetrics
	version            string
	relayManager       *relayManager
	punchy             *Punchy

	tryPromoteEvery uint32
	reQueryEvery    uint32
	reQueryWait     time.Duration

	ConntrackCacheTimeout time.Duration

	// CpuAffinity, when non-empty, names the CPUs each TUN reader goroutine
	// should pin to. Queue i pins to CpuAffinity[i % len(CpuAffinity)] —
	// shorter lists than `routines` cycle. Empty list keeps the default
	// pin-to-(i % NumCPU) behavior.
	CpuAffinity []int

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
	disconnectInvalid     atomic.Bool
	closed                atomic.Bool
	// cpuAffinity, when non-empty, names the CPUs each TUN reader goroutine
	// should pin to. Queue i pins to cpuAffinity[i % len(cpuAffinity)].
	// Empty falls back to the default pin-to-(i % NumCPU) behavior.
	cpuAffinity []int
	// ecnEnabled gates RFC 6040 underlay ECN propagation. When true,
	// inside.go copies the inner ECN onto the outer carrier on encap and
	// decryptToTun folds outer CE into the inner header on decap. Toggle
	// via tunnels.ecn (default true).
	ecnEnabled   atomic.Bool
	relayManager *relayManager

	tryPromoteEvery atomic.Uint32
	reQueryEvery    atomic.Uint32
	reQueryWait     atomic.Int64

	sendRecvErrorConfig   recvErrorConfig
	acceptRecvErrorConfig recvErrorConfig

	// rebindCount is used to decide if an active tunnel should trigger a punch notification through a lighthouse
	rebindCount int8
	version     string

	conntrackCacheTimeout time.Duration

	ctx     context.Context
	writers []udp.Conn
	readers []tio.Queue
	// batchers is one per tun queue, wrapping readers[i].
	// decryptToTun sends plaintext into the batch.RxBatcher;
	// listenOut calls its Flush at the end of each UDP recvmmsg batch.
	batchers []batch.RxBatcher
	wg       sync.WaitGroup

	// fatalErr holds the first unexpected reader error that caused shutdown.
	// nil means "no fatal error" (yet)
	fatalErr atomic.Pointer[error]
	// triggerShutdown is a function that will be run exactly once, when onFatal swaps something non-nil into fatalErr
	triggerShutdown func()

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics

	l *slog.Logger
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
		version:               c.version,
		writers:               make([]udp.Conn, c.routines),
		readers:               make([]tio.Queue, c.routines),
		batchers:              make([]batch.RxBatcher, c.routines),
		myVpnNetworks:         cs.myVpnNetworks,
		myVpnNetworksTable:    cs.myVpnNetworksTable,
		myVpnAddrs:            cs.myVpnAddrs,
		myVpnAddrsTable:       cs.myVpnAddrsTable,
		myBroadcastAddrsTable: cs.myVpnBroadcastAddrsTable,
		relayManager:          c.relayManager,
		connectionManager:     c.connectionManager,
		conntrackCacheTimeout: c.ConntrackCacheTimeout,
		cpuAffinity:           c.CpuAffinity,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
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
	)

	if f.routines > 1 {
		if !f.inside.SupportsMultiqueue() || !f.outside.SupportsMultipleReaders() {
			f.routines = 1
			f.l.Warn("routines is not supported on this platform, falling back to a single routine")
		}
	}

	metrics.GetOrRegisterGauge("routines", nil).Update(int64(f.routines))

	// Prepare n tun queues
	for i := 0; i < f.routines; i++ {
		if i > 0 {
			if err = f.inside.NewMultiQueueReader(); err != nil {
				return err
			}
		}
	}
	f.readers = f.inside.Readers()
	for i := range f.readers {
		caps := tio.QueueCapabilities(f.readers[i])
		if caps.TSO || caps.USO {
			// Multi-lane: TCP gets coalesced when TSO is on, UDP when USO
			// is on, everything else (and either lane disabled) falls
			// through to passthrough so non-IP / non-TCP-UDP traffic still
			// reaches the TUN.
			arena := batch.NewArena(batch.DefaultMultiArenaCap)
			f.batchers[i] = batch.NewMultiCoalescer(f.readers[i], f.l, arena, caps.TSO, caps.USO)
		} else {
			arena := batch.NewArena(batch.DefaultPassthroughArenaCap)
			f.batchers[i] = batch.NewPassthrough(f.readers[i], arena)
		}
	}

	f.wg.Add(1) // for us to wait on Close() to return
	if err = f.inside.Activate(); err != nil {
		f.wg.Done()
		f.inside.Close()
		return err
	}

	return nil
}

func (f *Interface) run() (func() error, error) {
	// Launch n queues to read packets from udp
	for i := 0; i < f.routines; i++ {
		f.wg.Go(func() {
			f.listenOut(i)
		})
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < f.routines; i++ {
		f.wg.Go(func() {
			f.listenIn(f.readers[i], i)
		})
	}

	return func() error {
		f.wg.Wait()
		if e := f.fatalErr.Load(); e != nil {
			return *e
		}
		return nil
	}, nil
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

func (f *Interface) listenOut(i int) {
	var li udp.Conn
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}

	ctCache := firewall.NewConntrackCacheTicker(f.ctx, f.l, f.conntrackCacheTimeout)
	lhh := f.lightHouse.NewRequestHandler()
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	listener := func(fromUdpAddr netip.AddrPort, payload []byte, meta udp.RxMeta) {
		f.readOutsidePackets(ViaSender{UdpAddr: fromUdpAddr}, payload, h, fwPacket, lhh, nb, i, ctCache.Get(), meta)
	}

	flusher := func() {
		if err := f.batchers[i].Flush(); err != nil {
			f.l.Error("Failed to flush tun coalescer", "error", err)
		}
	}

	err := li.ListenOut(listener, flusher)

	if err != nil && !f.closed.Load() {
		f.l.Error("Error while reading inbound packet, closing", "error", err)
		f.onFatal(err)
	}

	f.l.Debug("underlay reader is done", "reader", i)
}

func (f *Interface) listenIn(reader tio.Queue, i int) {
	// Pinning this thread (and goroutine) to a single CPU keeps every sendmmsg from this goroutine going through the
	// same TX ring on the nic, so the wire sees per-flow order.
	cpu := i % runtime.NumCPU()
	if n := len(f.cpuAffinity); n > 0 {
		cpu = f.cpuAffinity[i%n]
	}
	if err := util.PinThreadToCPU(cpu); err != nil {
		f.l.Warn("failed to pin tun reader to CPU", "queue", i, "cpu", cpu, "err", err)
	}

	rejectBuf := make([]byte, mtu)
	arenaSize := batch.SendBatchCap * (udp.MTU + 32)
	sb := batch.NewSendBatch(f.writers[i], batch.SendBatchCap, arenaSize)
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	conntrackCache := firewall.NewConntrackCacheTicker(f.ctx, f.l, f.conntrackCacheTimeout)

	for {
		pkts, err := reader.Read()
		if err != nil {
			if !f.closed.Load() {
				f.l.Error("Error while reading outbound packet, closing", "error", err, "reader", i)
				f.onFatal(err)
			}
			break
		}

		for _, pkt := range pkts {
			f.consumeInsidePacket(pkt, fwPacket, nb, sb, rejectBuf, i, conntrackCache.Get())
		}
		if err := sb.Flush(); err != nil {
			f.l.Error("Failed to write outgoing batch", "error", err, "writer", i)
		}
	}

	f.l.Debug("overlay reader is done", "reader", i)
}

func (f *Interface) RegisterConfigChangeCallbacks(c *config.C) {
	c.RegisterReloadCallback(f.reloadFirewall)
	c.RegisterReloadCallback(f.reloadSendRecvError)
	c.RegisterReloadCallback(f.reloadAcceptRecvError)
	c.RegisterReloadCallback(f.reloadDisconnectInvalid)
	c.RegisterReloadCallback(f.reloadMisc)
	c.RegisterReloadCallback(f.reloadEcn)

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
	//TODO: need to trigger/detect if the certificate changed too
	if c.HasChanged("firewall") == false {
		f.l.Debug("No firewall config change detected")
		return
	}

	fw, err := NewFirewallFromConfig(f.l, f.pki.getCertState(), c)
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

// reloadEcn syncs Interface.ecnEnabled with the tunnels.ecn config knob.
// Default is enabled (RFC 6040 normal mode); set false on the rare path
// where an underlay middlebox rewrites or drops ECN bits unpredictably.
func (f *Interface) reloadEcn(c *config.C) {
	initial := c.InitialLoad()
	if initial || c.HasChanged("tunnels.ecn") {
		v := c.GetBool("tunnels.ecn", true)
		f.ecnEnabled.Store(v)
		if !initial {
			f.l.Info("tunnels.ecn changed", "enabled", v)
		}
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
	var errs []error
	f.closed.Store(true)

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
	f.wg.Done()
	return errors.Join(errs...)
}
