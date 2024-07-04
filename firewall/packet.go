package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

type m map[string]interface{}

const (
	ProtoAny  = 0 // When we want to handle HOPOPT (0) we can change this, if ever
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoICMP = 1

	PortAny      = 0  // Special value for matching `port: any`
	PortFragment = -1 // Special value for matching `port: fragment`
)

type Packet struct {
	LocalIP    netip.Addr
	RemoteIP   netip.Addr
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
	Fragment   bool
}

func (fp *Packet) Copy() *Packet {
	return &Packet{
		LocalIP:    fp.LocalIP,
		RemoteIP:   fp.RemoteIP,
		LocalPort:  fp.LocalPort,
		RemotePort: fp.RemotePort,
		Protocol:   fp.Protocol,
		Fragment:   fp.Fragment,
	}
}

func (fp Packet) MarshalJSON() ([]byte, error) {
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
		"LocalIP":    fp.LocalIP.String(),
		"RemoteIP":   fp.RemoteIP.String(),
		"LocalPort":  fp.LocalPort,
		"RemotePort": fp.RemotePort,
		"Protocol":   proto,
		"Fragment":   fp.Fragment,
	})
}
