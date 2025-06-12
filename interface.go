package nebula

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
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

const mtu = 9001

type InterfaceConfig struct {
	HostMap                 *HostMap
	Outside                 udp.Conn
	Inside                  overlay.Device
	pki                     *PKI
	Firewall                *Firewall
	ServeDns                bool
	HandshakeManager        *HandshakeManager
	lightHouse              *LightHouse
	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	DropLocalBroadcast      bool
	DropMulticast           bool
	routines                int
	MessageMetrics          *MessageMetrics
	version                 string
	relayManager            *relayManager
	punchy                  *Punchy

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

		conntrackCacheTimeout: c.ConntrackCacheTimeout,

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

	ifce.connectionManager = newConnectionManager(ctx, c.l, ifce, c.checkInterval, c.pendingDeletionInterval, c.punchy)

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

	// Release the tun device
	return f.inside.Close()
}
