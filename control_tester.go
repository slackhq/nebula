// +build e2e_testing

package nebula

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// WaitForTypeByIndex will pipe all messages from this control device into the pipeTo control device
// returning after a message matching the criteria has been piped
func (c *Control) WaitForType(msgType NebulaMessageType, subType NebulaMessageSubType, pipeTo *Control) {
	h := &Header{}
	for {
		p := c.f.outside.Get(true)
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
func (c *Control) WaitForTypeByIndex(toIndex uint32, msgType NebulaMessageType, subType NebulaMessageSubType, pipeTo *Control) {
	h := &Header{}
	for {
		p := c.f.outside.Get(true)
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
func (c *Control) InjectLightHouseAddr(vpnIp net.IP, toAddr *net.UDPAddr) {
	c.f.lightHouse.Lock()
	remoteList := c.f.lightHouse.unlockedGetRemoteList(ip2int(vpnIp))
	remoteList.Lock()
	defer remoteList.Unlock()
	c.f.lightHouse.Unlock()

	iVpnIp := ip2int(vpnIp)
	if v4 := toAddr.IP.To4(); v4 != nil {
		remoteList.unlockedPrependV4(iVpnIp, NewIp4AndPort(v4, uint32(toAddr.Port)))
	} else {
		remoteList.unlockedPrependV6(iVpnIp, NewIp6AndPort(toAddr.IP, uint32(toAddr.Port)))
	}
}

// GetFromTun will pull a packet off the tun side of nebula
func (c *Control) GetFromTun(block bool) []byte {
	return c.f.inside.(*Tun).Get(block)
}

// GetFromUDP will pull a udp packet off the udp side of nebula
func (c *Control) GetFromUDP(block bool) *UdpPacket {
	return c.f.outside.Get(block)
}

func (c *Control) GetUDPTxChan() <-chan *UdpPacket {
	return c.f.outside.txPackets
}

func (c *Control) GetTunTxChan() <-chan []byte {
	return c.f.inside.(*Tun).txPackets
}

// InjectUDPPacket will inject a packet into the udp side of nebula
func (c *Control) InjectUDPPacket(p *UdpPacket) {
	c.f.outside.Send(p)
}

// InjectTunUDPPacket puts a udp packet on the tun interface. Using UDP here because it's a simpler protocol
func (c *Control) InjectTunUDPPacket(toIp net.IP, toPort uint16, fromPort uint16, data []byte) {
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    c.f.inside.CidrNet().IP,
		DstIP:    toIp,
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

	c.f.inside.(*Tun).Send(buffer.Bytes())
}

func (c *Control) GetUDPAddr() string {
	return c.f.outside.addr.String()
}

func (c *Control) KillPendingTunnel(vpnIp net.IP) bool {
	hostinfo, ok := c.f.handshakeManager.pendingHostMap.Hosts[ip2int(vpnIp)]
	if !ok {
		return false
	}

	c.f.handshakeManager.pendingHostMap.DeleteHostInfo(hostinfo)
	return true
}
