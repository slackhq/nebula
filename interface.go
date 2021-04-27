package nebula

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

const mtu = 9001

type Inside interface {
	io.ReadWriteCloser
	Activate() error
	CidrNet() *net.IPNet
	DeviceName() string
	WriteRaw([]byte) error
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}

type InterfaceConfig struct {
	HostMap                 *HostMap
	Outside                 *udpConn
	Inside                  Inside
	certState               *CertState
	Cipher                  string
	Firewall                *Firewall
	ServeDns                bool
	HandshakeManager        *HandshakeManager
	lightHouse              *LightHouse
	checkInterval           int
	pendingDeletionInterval int
	DropLocalBroadcast      bool
	DropMulticast           bool
	UDPBatchSize            int
	routines                int
	MessageMetrics          *MessageMetrics
	version                 string
	caPool                  *cert.NebulaCAPool

	ConntrackCacheTimeout time.Duration
	l                     *logrus.Logger
}

type Interface struct {
	hostMap            *HostMap
	outside            *udpConn
	inside             Inside
	certState          *CertState
	cipher             string
	firewall           *Firewall
	connectionManager  *connectionManager
	handshakeManager   *HandshakeManager
	serveDns           bool
	createTime         time.Time
	lightHouse         *LightHouse
	localBroadcast     uint32
	myVpnIp            uint32
	dropLocalBroadcast bool
	dropMulticast      bool
	udpBatchSize       int
	routines           int
	caPool             *cert.NebulaCAPool

	// rebindCount is used to decide if an active tunnel should trigger a punch notification through a lighthouse
	rebindCount int8
	version     string

	conntrackCacheTimeout time.Duration

	writers []*udpConn
	readers []io.ReadWriteCloser

	metricHandshakes    metrics.Histogram
	messageMetrics      *MessageMetrics
	cachedPacketMetrics *cachedPacketMetrics

	l *logrus.Logger
}

func NewInterface(c *InterfaceConfig) (*Interface, error) {
	if c.Outside == nil {
		return nil, errors.New("no outside connection")
	}
	if c.Inside == nil {
		return nil, errors.New("no inside interface (tun)")
	}
	if c.certState == nil {
		return nil, errors.New("no certificate state")
	}
	if c.Firewall == nil {
		return nil, errors.New("no firewall rules")
	}

	ifce := &Interface{
		hostMap:            c.HostMap,
		outside:            c.Outside,
		inside:             c.Inside,
		certState:          c.certState,
		cipher:             c.Cipher,
		firewall:           c.Firewall,
		serveDns:           c.ServeDns,
		handshakeManager:   c.HandshakeManager,
		createTime:         time.Now(),
		lightHouse:         c.lightHouse,
		localBroadcast:     ip2int(c.certState.certificate.Details.Ips[0].IP) | ^ip2int(c.certState.certificate.Details.Ips[0].Mask),
		dropLocalBroadcast: c.DropLocalBroadcast,
		dropMulticast:      c.DropMulticast,
		udpBatchSize:       c.UDPBatchSize,
		routines:           c.routines,
		version:            c.version,
		writers:            make([]*udpConn, c.routines),
		readers:            make([]io.ReadWriteCloser, c.routines),
		caPool:             c.caPool,
		myVpnIp:            ip2int(c.certState.certificate.Details.Ips[0].IP),

		conntrackCacheTimeout: c.ConntrackCacheTimeout,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		messageMetrics:   c.MessageMetrics,
		cachedPacketMetrics: &cachedPacketMetrics{
			sent:    metrics.GetOrRegisterCounter("hostinfo.cached_packets.sent", nil),
			dropped: metrics.GetOrRegisterCounter("hostinfo.cached_packets.dropped", nil),
		},

		l: c.l,
	}

	ifce.connectionManager = newConnectionManager(c.l, ifce, c.checkInterval, c.pendingDeletionInterval)

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

	f.l.WithField("interface", f.inside.DeviceName()).WithField("network", f.inside.CidrNet().String()).
		WithField("build", f.version).WithField("udpAddr", addr).
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

	var li *udpConn
	// TODO clean this up with a coherent interface for each outside connection
	if i > 0 {
		li = f.writers[i]
	} else {
		li = f.outside
	}
	li.ListenOut(f, i)
}

func (f *Interface) listenIn(reader io.ReadWriteCloser, i int) {
	runtime.LockOSThread()

	packet := make([]byte, mtu)
	out := make([]byte, mtu)
	fwPacket := &FirewallPacket{}
	nb := make([]byte, 12, 12)

	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)

	for {
		n, err := reader.Read(packet)
		if err != nil {
			f.l.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}

		f.consumeInsidePacket(packet[:n], fwPacket, nb, out, i, conntrackCache.Get(f.l))
	}
}

func (f *Interface) RegisterConfigChangeCallbacks(c *Config) {
	c.RegisterReloadCallback(f.reloadCA)
	c.RegisterReloadCallback(f.reloadCertKey)
	c.RegisterReloadCallback(f.reloadFirewall)
	for _, udpConn := range f.writers {
		c.RegisterReloadCallback(udpConn.reloadConfig)
	}
}

func (f *Interface) reloadCA(c *Config) {
	// reload and check regardless
	// todo: need mutex?
	newCAs, err := loadCAFromConfig(f.l, c)
	if err != nil {
		f.l.WithError(err).Error("Could not refresh trusted CA certificates")
		return
	}

	f.caPool = newCAs
	f.l.WithField("fingerprints", f.caPool.GetFingerprints()).Info("Trusted CA certificates refreshed")
}

func (f *Interface) reloadCertKey(c *Config) {
	// reload and check in all cases
	cs, err := NewCertStateFromConfig(c)
	if err != nil {
		f.l.WithError(err).Error("Could not refresh client cert")
		return
	}

	// did IP in cert change? if so, don't set
	oldIPs := f.certState.certificate.Details.Ips
	newIPs := cs.certificate.Details.Ips
	if len(oldIPs) > 0 && len(newIPs) > 0 && oldIPs[0].String() != newIPs[0].String() {
		f.l.WithField("new_ip", newIPs[0]).WithField("old_ip", oldIPs[0]).Error("IP in new cert was different from old")
		return
	}

	f.certState = cs
	f.l.WithField("cert", cs.certificate).Info("Client cert refreshed from disk")
}

func (f *Interface) reloadFirewall(c *Config) {
	//TODO: need to trigger/detect if the certificate changed too
	if c.HasChanged("firewall") == false {
		f.l.Debug("No firewall config change detected")
		return
	}

	fw, err := NewFirewallFromConfig(f.l, f.certState.certificate, c)
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
		f.l.WithField("firewallHash", fw.GetRuleHash()).
			WithField("oldFirewallHash", oldFw.GetRuleHash()).
			WithField("rulesVersion", fw.rulesVersion).
			Warn("firewall rulesVersion has overflowed, resetting conntrack")
	} else {
		fw.Conntrack = conntrack
	}

	f.firewall = fw

	oldFw.Destroy()
	f.l.WithField("firewallHash", fw.GetRuleHash()).
		WithField("oldFirewallHash", oldFw.GetRuleHash()).
		WithField("rulesVersion", fw.rulesVersion).
		Info("New firewall has been installed")
}

func (f *Interface) emitStats(i time.Duration) {
	ticker := time.NewTicker(i)

	udpStats := NewUDPStatsEmitter(f.writers)

	for range ticker.C {
		f.firewall.EmitStats()
		f.handshakeManager.EmitStats()

		udpStats()
	}
}
