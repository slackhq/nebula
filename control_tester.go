//go:build e2e_testing

package nebula

import (
	"net/netip"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/udp"
)

// WaitForType will pipe all messages from this control device into the pipeTo control device
// returning after a message matching the criteria has been piped
func (c *Control) WaitForType(msgType header.MessageType, subType header.MessageSubType, pipeTo *Control) {
	h := &header.H{}
	for {
		p := c.f.outside.(*udp.TesterConn).Get(true)
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		pipeTo.InjectUDPPacket(p)
		match := h.Type == msgType && h.Subtype == subType
		p.Release()
		if match {
			return
		}
	}
}

// WaitForTypeByIndex is similar to WaitForType except it adds an index check
// Useful if you have many nodes communicating and want to wait to find a specific nodes packet
func (c *Control) WaitForTypeByIndex(toIndex uint32, msgType header.MessageType, subType header.MessageSubType, pipeTo *Control) {
	h := &header.H{}
	for {
		p := c.f.outside.(*udp.TesterConn).Get(true)
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		pipeTo.InjectUDPPacket(p)
		match := h.RemoteIndex == toIndex && h.Type == msgType && h.Subtype == subType
		p.Release()
		if match {
			return
		}
	}
}

// InjectLightHouseAddr will push toAddr into the local lighthouse cache for the vpnIp
// This is necessary if you did not configure static hosts or are not running a lighthouse
func (c *Control) InjectLightHouseAddr(vpnIp netip.Addr, toAddr netip.AddrPort) {
	c.f.lightHouse.Lock()
	remoteList := c.f.lightHouse.unlockedGetRemoteList([]netip.Addr{vpnIp})
	remoteList.Lock()
	defer remoteList.Unlock()
	c.f.lightHouse.Unlock()

	if toAddr.Addr().Is4() {
		remoteList.unlockedPrependV4(vpnIp, netAddrToProtoV4AddrPort(toAddr.Addr(), toAddr.Port()))
	} else {
		remoteList.unlockedPrependV6(vpnIp, netAddrToProtoV6AddrPort(toAddr.Addr(), toAddr.Port()))
	}
}

// InjectRelays will push relayVpnIps into the local lighthouse cache for the vpnIp
// This is necessary to inform an initiator of possible relays for communicating with a responder
func (c *Control) InjectRelays(vpnIp netip.Addr, relayVpnIps []netip.Addr) {
	c.f.lightHouse.Lock()
	remoteList := c.f.lightHouse.unlockedGetRemoteList([]netip.Addr{vpnIp})
	remoteList.Lock()
	defer remoteList.Unlock()
	c.f.lightHouse.Unlock()

	remoteList.unlockedSetRelay(vpnIp, relayVpnIps)
}

// GetFromTun will pull a packet off the tun side of nebula
func (c *Control) GetFromTun(block bool) []byte {
	return c.f.inside.(*overlay.TestTun).Get(block)
}

// GetFromUDP will pull a udp packet off the udp side of nebula
func (c *Control) GetFromUDP(block bool) *udp.Packet {
	return c.f.outside.(*udp.TesterConn).Get(block)
}

func (c *Control) GetUDPTxChan() <-chan *udp.Packet {
	return c.f.outside.(*udp.TesterConn).TxPackets
}

func (c *Control) GetTunTxChan() <-chan []byte {
	return c.f.inside.(*overlay.TestTun).TxPackets
}

// InjectUDPPacket injects a packet into the udp side. We copy internally so the caller keeps ownership of p.
// The copy comes from the freelist so steady-state alloc is zero.
func (c *Control) InjectUDPPacket(p *udp.Packet) {
	c.f.outside.(*udp.TesterConn).Send(p.Copy())
}

// InjectTunPacket pushes an IP packet onto the tun interface.
func (c *Control) InjectTunPacket(packet []byte) {
	c.f.inside.(*overlay.TestTun).Send(packet)
}

func (c *Control) GetVpnAddrs() []netip.Addr {
	return c.f.myVpnAddrs
}

func (c *Control) GetUDPAddr() netip.AddrPort {
	return c.f.outside.(*udp.TesterConn).Addr
}

func (c *Control) KillPendingTunnel(vpnIp netip.Addr) bool {
	hostinfo := c.f.handshakeManager.QueryVpnAddr(vpnIp)
	if hostinfo == nil {
		return false
	}

	c.f.handshakeManager.DeleteHostInfo(hostinfo)
	return true
}

func (c *Control) GetHostmap() *HostMap {
	return c.f.hostMap
}

func (c *Control) GetF() *Interface {
	return c.f
}

func (c *Control) GetCertState() *CertState {
	return c.f.pki.getCertState()
}

func (c *Control) ReHandshake(vpnIp netip.Addr) {
	c.f.handshakeManager.StartHandshake(vpnIp, nil)
}
