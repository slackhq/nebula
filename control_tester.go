//go:build e2e_testing
// +build e2e_testing

package nebula

import (
	"net/netip"

	"github.com/slackhq/nebula/cert"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		if h.Type == msgType && h.Subtype == subType {
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
		if h.RemoteIndex == toIndex && h.Type == msgType && h.Subtype == subType {
			return
		}
	}
}

// InjectLightHouseAddr will push toAddr into the local lighthouse cache for the vpnIp
// This is necessary if you did not configure static hosts or are not running a lighthouse
func (c *Control) InjectLightHouseAddr(vpnIp netip.Addr, toAddr netip.AddrPort) {
	c.f.lightHouse.Lock()
	remoteList := c.f.lightHouse.unlockedGetRemoteList(vpnIp)
	remoteList.Lock()
	defer remoteList.Unlock()
	c.f.lightHouse.Unlock()

	if toAddr.Addr().Is4() {
		remoteList.unlockedPrependV4(vpnIp, NewIp4AndPortFromNetIP(toAddr.Addr(), toAddr.Port()))
	} else {
		remoteList.unlockedPrependV6(vpnIp, NewIp6AndPortFromNetIP(toAddr.Addr(), toAddr.Port()))
	}
}

// InjectRelays will push relayVpnIps into the local lighthouse cache for the vpnIp
// This is necessary to inform an initiator of possible relays for communicating with a responder
func (c *Control) InjectRelays(vpnIp netip.Addr, relayVpnIps []netip.Addr) {
	c.f.lightHouse.Lock()
	remoteList := c.f.lightHouse.unlockedGetRemoteList(vpnIp)
	remoteList.Lock()
	defer remoteList.Unlock()
	c.f.lightHouse.Unlock()

	remoteList.unlockedSetRelay(vpnIp, vpnIp, relayVpnIps)
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

// InjectUDPPacket will inject a packet into the udp side of nebula
func (c *Control) InjectUDPPacket(p *udp.Packet) {
	c.f.outside.(*udp.TesterConn).Send(p)
}

// InjectTunUDPPacket puts a udp packet on the tun interface. Using UDP here because it's a simpler protocol
func (c *Control) InjectTunUDPPacket(toIp netip.Addr, toPort uint16, fromPort uint16, data []byte) {
	//TODO: IPV6-WORK
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    c.f.inside.Cidr().Addr().Unmap().AsSlice(),
		DstIP:    toIp.Unmap().AsSlice(),
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(fromPort),
		DstPort: layers.UDPPort(toPort),
	}
	err := udp.SetNetworkLayerForChecksum(&ip)
	if err != nil {
		panic(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buffer, opt, &ip, &udp, gopacket.Payload(data))
	if err != nil {
		panic(err)
	}

	c.f.inside.(*overlay.TestTun).Send(buffer.Bytes())
}

func (c *Control) GetVpnIp() netip.Addr {
	return c.f.myVpnNet.Addr()
}

func (c *Control) GetUDPAddr() netip.AddrPort {
	return c.f.outside.(*udp.TesterConn).Addr
}

func (c *Control) KillPendingTunnel(vpnIp netip.Addr) bool {
	hostinfo := c.f.handshakeManager.QueryVpnIp(vpnIp)
	if hostinfo == nil {
		return false
	}

	c.f.handshakeManager.DeleteHostInfo(hostinfo)
	return true
}

func (c *Control) GetHostmap() *HostMap {
	return c.f.hostMap
}

func (c *Control) GetCert() *cert.NebulaCertificate {
	return c.f.pki.GetCertState().Certificate
}

func (c *Control) ReHandshake(vpnIp netip.Addr) {
	c.f.handshakeManager.StartHandshake(vpnIp, nil)
}
