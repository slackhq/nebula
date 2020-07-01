package nebula

import (
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
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
	version            string

	sigChan chan os.Signal

	metricHandshakes metrics.Histogram
	messageMetrics   *MessageMetrics
}

type killSignal struct {
	cb chan struct{}
}

func (s killSignal) Signal() {}
func (s killSignal) String() string {
	return "controlling app"
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
		sigChan:            make(chan os.Signal),
		version:            c.version,

		metricHandshakes: metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015)),
		messageMetrics:   c.MessageMetrics,
	}

	ifce.connectionManager = newConnectionManager(ifce, c.checkInterval, c.pendingDeletionInterval)

	return ifce, nil
}

func (f *Interface) ShutdownBlock() {
	signal.Notify(f.sigChan, syscall.SIGTERM)
	signal.Notify(f.sigChan, syscall.SIGINT)

	rawSig := <-f.sigChan
	sig := rawSig.String()
	l.WithField("signal", sig).Info("Caught signal, shutting down")

	//TODO: stop tun and udp routines, the lock on hostMap effectively does that though
	//TODO: this is probably better as a function in ConnectionManager or HostMap directly
	f.hostMap.Lock()
	for _, h := range f.hostMap.Hosts {
		if h.ConnectionState.ready {
			f.send(closeTunnel, 0, h.ConnectionState, h, h.remote, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
			l.WithField("vpnIp", IntIp(h.hostId)).WithField("udpAddr", h.remote).
				Debug("Sending close tunnel message")
		}
	}
	f.hostMap.Unlock()

	//TODO: move goodbye to cmd
	l.WithField("signal", sig).Info("Goodbye")
	if s, ok := rawSig.(killSignal); ok {
		s.cb <- struct{}{}
	}
}

func (f *Interface) Run() {
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

	// Listen on for incoming packets from the world
	go f.outside.ListenOut(f)

	// Listen for incoming packets from this machine
	go f.listenIn()
}

func (f *Interface) Stop() {
	cb := make(chan struct{})
	//TODO: instead of blocking on ShutdownBlock ending we should have a channel for each goroutine to block on returning
	f.sigChan <- killSignal{cb: cb}
	<-cb
}

func (f *Interface) listenIn() {
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
	if c.HasChanged("firewall") == false {
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
