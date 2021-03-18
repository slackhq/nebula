package udp

//TODO: This belongs in a firewall package when it exists

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

const (
	ProtoAny  = 0 // When we want to handle HOPOPT (0) we can change this, if ever
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoICMP = 1
)

type FirewallPacket struct {
	LocalIP    uint32
	RemoteIP   uint32
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
	Fragment   bool
}

func (fp *FirewallPacket) Copy() *FirewallPacket {
	return &FirewallPacket{
		LocalIP:    fp.LocalIP,
		RemoteIP:   fp.RemoteIP,
		LocalPort:  fp.LocalPort,
		RemotePort: fp.RemotePort,
		Protocol:   fp.Protocol,
		Fragment:   fp.Fragment,
	}
}

func (fp FirewallPacket) MarshalJSON() ([]byte, error) {
	var proto string
	switch fp.Protocol {
	case ProtoTCP:
		proto = "tcp"
	case ProtoICMP:
		proto = "icmp"
	case ProtoUDP:
		proto = "udp"
	default:
		proto = fmt.Sprintf("unknown %v", fp.Protocol)
	}
	return json.Marshal(m{
		"LocalIP":    int2ip(fp.LocalIP).String(),
		"RemoteIP":   int2ip(fp.RemoteIP).String(),
		"LocalPort":  fp.LocalPort,
		"RemotePort": fp.RemotePort,
		"Protocol":   proto,
		"Fragment":   fp.Fragment,
	})
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
