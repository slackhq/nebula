package nebula

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/rcrowley/go-metrics"
)

const mtu = 9001

type Inside interface {
	io.ReadWriteCloser
	Activate() error
	CidrNet() *net.IPNet
	DeviceName() string
	WriteRaw([]byte) error
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
	udpQueues               int
	tunQueues               int
	MessageMetrics          *MessageMetrics
	version                 string
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
	dropLocalBroadcast bool
	dropMulticast      bool
	udpBatchSize       int
	udpQueues          int
	tunQueues          int
	version            string

	metricHandshakes metrics.Histogram
	messageMetrics   *MessageMetrics
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
		udpQueues:          c.udpQueues,
		tunQueues:          c.tunQueues,
		version:            c.version,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		messageMetrics:   c.MessageMetrics,
	}

	ifce.connectionManager = newConnectionManager(ifce, c.checkInterval, c.pendingDeletionInterval)

	return ifce, nil
}

func (f *Interface) run() {
	// actually turn on tun dev
	if err := f.inside.Activate(); err != nil {
		l.Fatal(err)
	}

	addr, err := f.outside.LocalAddr()
	if err != nil {
		l.WithError(err).Error("Failed to get udp listen address")
	}

	l.WithField("interface", f.inside.DeviceName()).WithField("network", f.inside.CidrNet().String()).
		WithField("build", f.version).WithField("udpAddr", addr).
		Info("Nebula interface is active")

	// Launch n queues to read packets from udp
	for i := 0; i < f.udpQueues; i++ {
		go f.listenOut(i)
	}

	// Launch n queues to read packets from tun dev
	for i := 0; i < f.tunQueues; i++ {
		go f.listenIn(i)
	}
}

func (f *Interface) listenOut(i int) {
	//TODO: handle error
	addr, err := f.outside.LocalAddr()
	if err != nil {
		l.WithError(err).Error("failed to discover udp listening address")
	}

	var li *udpConn
	if i > 0 {
		//TODO: handle error
		li, err = NewListener(udp2ip(addr).String(), int(addr.Port), i > 0)
		if err != nil {
			l.WithError(err).Error("failed to make a new udp listener")
		}
	} else {
		li = f.outside
	}

	li.ListenOut(f)
}

func (f *Interface) listenIn(i int) {
	packet := make([]byte, mtu)
	out := make([]byte, mtu)
	fwPacket := &FirewallPacket{}
	nb := make([]byte, 12, 12)

	for {
		n, err := f.inside.Read(packet)
		if err != nil {
			l.WithError(err).Error("Error while reading outbound packet")
			// This only seems to happen when something fatal happens to the fd, so exit.
			os.Exit(2)
		}

		f.consumeInsidePacket(packet[:n], fwPacket, nb, out)
	}
}

func (f *Interface) RegisterConfigChangeCallbacks(c *Config) {
	c.RegisterReloadCallback(f.reloadCA)
	c.RegisterReloadCallback(f.reloadCertKey)
	c.RegisterReloadCallback(f.reloadFirewall)
	c.RegisterReloadCallback(f.outside.reloadConfig)
}

func (f *Interface) reloadCA(c *Config) {
	// reload and check regardless
	// todo: need mutex?
	newCAs, err := loadCAFromConfig(c)
	if err != nil {
		l.WithError(err).Error("Could not refresh trusted CA certificates")
		return
	}

	trustedCAs = newCAs
	l.WithField("fingerprints", trustedCAs.GetFingerprints()).Info("Trusted CA certificates refreshed")
}

func (f *Interface) reloadCertKey(c *Config) {
	// reload and check in all cases
	cs, err := NewCertStateFromConfig(c)
	if err != nil {
		l.WithError(err).Error("Could not refresh client cert")
		return
	}

	// did IP in cert change? if so, don't set
	oldIPs := f.certState.certificate.Details.Ips
	newIPs := cs.certificate.Details.Ips
	if len(oldIPs) > 0 && len(newIPs) > 0 && oldIPs[0].String() != newIPs[0].String() {
		l.WithField("new_ip", newIPs[0]).WithField("old_ip", oldIPs[0]).Error("IP in new cert was different from old")
		return
	}

	f.certState = cs
	l.WithField("cert", cs.certificate).Info("Client cert refreshed from disk")
}

func (f *Interface) reloadFirewall(c *Config) {
	//TODO: need to trigger/detect if the certificate changed too
	if !c.HasChanged("firewall") {
		l.Debug("No firewall config change detected")
		return
	}

	fw, err := NewFirewallFromConfig(f.certState.certificate, c)
	if err != nil {
		l.WithError(err).Error("Error while creating firewall during reload")
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
		l.WithField("firewallHash", fw.GetRuleHash()).
			WithField("oldFirewallHash", oldFw.GetRuleHash()).
			WithField("rulesVersion", fw.rulesVersion).
			Warn("firewall rulesVersion has overflowed, resetting conntrack")
	} else {
		fw.Conntrack = conntrack
	}

	f.firewall = fw

	oldFw.Destroy()
	l.WithField("firewallHash", fw.GetRuleHash()).
		WithField("oldFirewallHash", oldFw.GetRuleHash()).
		WithField("rulesVersion", fw.rulesVersion).
		Info("New firewall has been installed")
}

func (f *Interface) emitStats(i time.Duration) {
	ticker := time.NewTicker(i)
	for range ticker.C {
		f.firewall.EmitStats()
		f.handshakeManager.EmitStats()
	}
}
