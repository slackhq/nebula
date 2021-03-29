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
	c.f.lightHouse.AddRemote(ip2int(vpnIp), &udpAddr{IP: toAddr.IP, Port: uint16(toAddr.Port)}, false)
}

// GetFromTun will pull a packet off the tun side of nebula
func (c *Control) GetFromTun(block bool) []byte {
	return c.f.inside.(*Tun).Get(block)
}

// GetFromUDP will pull a udp packet off the udp side of nebula
func (c *Control) GetFromUDP(block bool) *UdpPacket {
	return c.f.outside.Get(block)
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
	udp.SetNetworkLayerForChecksum(&ip)

	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := gopacket.SerializeLayers(buffer, opt, &ip, &udp, gopacket.Payload(data))
	if err != nil {
		panic(err)
	}

	c.f.inside.(*Tun).Send(buffer.Bytes())
}
