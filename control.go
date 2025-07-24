package nebula

import (
	"context"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
)

// Every interaction here needs to take extra care to copy memory and not return or use arguments "as is" when touching
// core. This means copying IP objects, slices, de-referencing pointers and taking the actual value, etc

type controlEach func(h *HostInfo)

type controlHostLister interface {
	QueryVpnAddr(vpnAddr netip.Addr) *HostInfo
	ForEachIndex(each controlEach)
	ForEachVpnAddr(each controlEach)
	GetPreferredRanges() []netip.Prefix
}

type Control struct {
	f                      *Interface
	l                      *logrus.Logger
	ctx                    context.Context
	cancel                 context.CancelFunc
	sshStart               func()
	statsStart             func()
	dnsStart               func()
	lighthouseStart        func()
	connectionManagerStart func(context.Context)
}

type ControlHostInfo struct {
	VpnAddrs               []netip.Addr     `json:"vpnAddrs"`
	LocalIndex             uint32           `json:"localIndex"`
	RemoteIndex            uint32           `json:"remoteIndex"`
	RemoteAddrs            []netip.AddrPort `json:"remoteAddrs"`
	Cert                   cert.Certificate `json:"cert"`
	MessageCounter         uint64           `json:"messageCounter"`
	CurrentRemote          netip.AddrPort   `json:"currentRemote"`
	CurrentRelaysToMe      []netip.Addr     `json:"currentRelaysToMe"`
	CurrentRelaysThroughMe []netip.Addr     `json:"currentRelaysThroughMe"`
}

// Start actually runs nebula, this is a nonblocking call. To block use Control.ShutdownBlock()
func (c *Control) Start() {
	// Activate the interface
	c.f.activate()

	// Call all the delayed funcs that waited patiently for the interface to be created.
	if c.sshStart != nil {
		go c.sshStart()
	}
	if c.statsStart != nil {
		go c.statsStart()
	}
	if c.dnsStart != nil {
		go c.dnsStart()
	}
	if c.connectionManagerStart != nil {
		go c.connectionManagerStart(c.ctx)
	}
	if c.lighthouseStart != nil {
		c.lighthouseStart()
	}

	// Start reading packets.
	c.f.run()
}

func (c *Control) Context() context.Context {
	return c.ctx
}

// Stop signals nebula to shutdown and close all tunnels, returns after the shutdown is complete
func (c *Control) Stop() {
	// Stop the handshakeManager (and other services), to prevent new tunnels from
	// being created while we're shutting them all down.
	c.cancel()

	c.CloseAllTunnels(false)
	if err := c.f.Close(); err != nil {
		c.l.WithError(err).Error("Close interface failed")
	}
	c.l.Info("Goodbye")
}

// ShutdownBlock will listen for and block on term and interrupt signals, calling Control.Stop() once signalled
func (c *Control) ShutdownBlock() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)

	rawSig := <-sigChan
	sig := rawSig.String()
	c.l.WithField("signal", sig).Info("Caught signal, shutting down")
	c.Stop()
}

// RebindUDPServer asks the UDP listener to rebind it's listener. Mainly used on mobile clients when interfaces change
func (c *Control) RebindUDPServer() {
	_ = c.f.outside.Rebind()

	// Trigger a lighthouse update, useful for mobile clients that should have an update interval of 0
	c.f.lightHouse.SendUpdate()

	// Let the main interface know that we rebound so that underlying tunnels know to trigger punches from their remotes
	c.f.rebindCount++
}

// ListHostmapHosts returns details about the actual or pending (handshaking) hostmap by vpn ip
func (c *Control) ListHostmapHosts(pendingMap bool) []ControlHostInfo {
	if pendingMap {
		return listHostMapHosts(c.f.handshakeManager)
	} else {
		return listHostMapHosts(c.f.hostMap)
	}
}

// ListHostmapIndexes returns details about the actual or pending (handshaking) hostmap by local index id
func (c *Control) ListHostmapIndexes(pendingMap bool) []ControlHostInfo {
	if pendingMap {
		return listHostMapIndexes(c.f.handshakeManager)
	} else {
		return listHostMapIndexes(c.f.hostMap)
	}
}

// GetCertByVpnIp returns the authenticated certificate of the given vpn IP, or nil if not found
func (c *Control) GetCertByVpnIp(vpnIp netip.Addr) cert.Certificate {
	if c.f.myVpnAddrsTable.Contains(vpnIp) {
		// Only returning the default certificate since its impossible
		// for any other host but ourselves to have more than 1
		return c.f.pki.getCertState().GetDefaultCertificate().Copy()
	}
	hi := c.f.hostMap.QueryVpnAddr(vpnIp)
	if hi == nil {
		return nil
	}
	return hi.GetCert().Certificate.Copy()
}

// CreateTunnel creates a new tunnel to the given vpn ip.
func (c *Control) CreateTunnel(vpnIp netip.Addr) {
	c.f.handshakeManager.StartHandshake(vpnIp, nil)
}

// PrintTunnel creates a new tunnel to the given vpn ip.
func (c *Control) PrintTunnel(vpnIp netip.Addr) *ControlHostInfo {
	hi := c.f.hostMap.QueryVpnAddr(vpnIp)
	if hi == nil {
		return nil
	}
	chi := copyHostInfo(hi, c.f.hostMap.GetPreferredRanges())
	return &chi
}

// QueryLighthouse queries the lighthouse.
func (c *Control) QueryLighthouse(vpnIp netip.Addr) *CacheMap {
	hi := c.f.lightHouse.Query(vpnIp)
	if hi == nil {
		return nil
	}
	return hi.CopyCache()
}

// GetHostInfoByVpnAddr returns a single tunnels hostInfo, or nil if not found
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) GetHostInfoByVpnAddr(vpnAddr netip.Addr, pending bool) *ControlHostInfo {
	var hl controlHostLister
	if pending {
		hl = c.f.handshakeManager
	} else {
		hl = c.f.hostMap
	}

	h := hl.QueryVpnAddr(vpnAddr)
	if h == nil {
		return nil
	}

	ch := copyHostInfo(h, c.f.hostMap.GetPreferredRanges())
	return &ch
}

// SetRemoteForTunnel forces a tunnel to use a specific remote
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) SetRemoteForTunnel(vpnIp netip.Addr, addr netip.AddrPort) *ControlHostInfo {
	hostInfo := c.f.hostMap.QueryVpnAddr(vpnIp)
	if hostInfo == nil {
		return nil
	}

	hostInfo.SetRemote(addr)
	ch := copyHostInfo(hostInfo, c.f.hostMap.GetPreferredRanges())
	return &ch
}

// CloseTunnel closes a fully established tunnel. If localOnly is false it will notify the remote end as well.
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) CloseTunnel(vpnIp netip.Addr, localOnly bool) bool {
	hostInfo := c.f.hostMap.QueryVpnAddr(vpnIp)
	if hostInfo == nil {
		return false
	}

	if !localOnly {
		c.f.send(
			header.CloseTunnel,
			0,
			hostInfo.ConnectionState,
			hostInfo,
			[]byte{},
			make([]byte, 12, 12),
			make([]byte, mtu),
		)
	}

	c.f.closeTunnel(hostInfo)
	return true
}

// CloseAllTunnels is just like CloseTunnel except it goes through and shuts them all down, optionally you can avoid shutting down lighthouse tunnels
// the int returned is a count of tunnels closed
func (c *Control) CloseAllTunnels(excludeLighthouses bool) (closed int) {
	shutdown := func(h *HostInfo) {
		if excludeLighthouses && c.f.lightHouse.IsAnyLighthouseAddr(h.vpnAddrs) {
			return
		}
		c.f.send(header.CloseTunnel, 0, h.ConnectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
		c.f.closeTunnel(h)

		c.l.WithField("vpnAddrs", h.vpnAddrs).WithField("udpAddr", h.remote).
			Debug("Sending close tunnel message")
		closed++
	}

	// Learn which hosts are being used as relays, so we can shut them down last.
	relayingHosts := map[netip.Addr]*HostInfo{}
	// Grab the hostMap lock to access the Relays map
	c.f.hostMap.Lock()
	for _, relayingHost := range c.f.hostMap.Relays {
		relayingHosts[relayingHost.vpnAddrs[0]] = relayingHost
	}
	c.f.hostMap.Unlock()

	hostInfos := []*HostInfo{}
	// Grab the hostMap lock to access the Hosts map
	c.f.hostMap.Lock()
	for _, relayHost := range c.f.hostMap.Indexes {
		if _, ok := relayingHosts[relayHost.vpnAddrs[0]]; !ok {
			hostInfos = append(hostInfos, relayHost)
		}
	}
	c.f.hostMap.Unlock()

	for _, h := range hostInfos {
		shutdown(h)
	}
	for _, h := range relayingHosts {
		shutdown(h)
	}
	return
}

func (c *Control) Device() overlay.Device {
	return c.f.inside
}

func copyHostInfo(h *HostInfo, preferredRanges []netip.Prefix) ControlHostInfo {
	chi := ControlHostInfo{
		VpnAddrs:               make([]netip.Addr, len(h.vpnAddrs)),
		LocalIndex:             h.localIndexId,
		RemoteIndex:            h.remoteIndexId,
		RemoteAddrs:            h.remotes.CopyAddrs(preferredRanges),
		CurrentRelaysToMe:      h.relayState.CopyRelayIps(),
		CurrentRelaysThroughMe: h.relayState.CopyRelayForIps(),
		CurrentRemote:          h.remote,
	}

	for i, a := range h.vpnAddrs {
		chi.VpnAddrs[i] = a
	}

	if h.ConnectionState != nil {
		chi.MessageCounter = h.ConnectionState.messageCounter.Load()
	}

	if c := h.GetCert(); c != nil {
		chi.Cert = c.Certificate.Copy()
	}

	return chi
}

func listHostMapHosts(hl controlHostLister) []ControlHostInfo {
	hosts := make([]ControlHostInfo, 0)
	pr := hl.GetPreferredRanges()
	hl.ForEachVpnAddr(func(hostinfo *HostInfo) {
		hosts = append(hosts, copyHostInfo(hostinfo, pr))
	})
	return hosts
}

func listHostMapIndexes(hl controlHostLister) []ControlHostInfo {
	hosts := make([]ControlHostInfo, 0)
	pr := hl.GetPreferredRanges()
	hl.ForEachIndex(func(hostinfo *HostInfo) {
		hosts = append(hosts, copyHostInfo(hostinfo, pr))
	})
	return hosts
}
