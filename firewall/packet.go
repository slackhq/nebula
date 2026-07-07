package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

type m = map[string]any

const (
	ProtoAny    = 0 // When we want to handle HOPOPT (0) we can change this, if ever
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMP   = 1
	ProtoICMPv6 = 58

	PortAny      = 0  // Special value for matching `port: any`
	PortFragment = -1 // Special value for matching `port: fragment`
)

type Packet struct {
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	// LocalPort is the destination port for incoming traffic, or the source port for outgoing. Zero for ICMP.
	LocalPort uint16
	// RemotePort is the source port for incoming traffic, or the destination port for outgoing.
	// For ICMP, it's the "identifier". This is only used for connection tracking, actual firewall rules will not filter on ICMP identifier
	RemotePort uint16
	Protocol   uint8
	Fragment   bool
}

// PacketContext carries additional parsed details about a packet that are
// useful for event reporting but deliberately kept out of Packet so Packet
// can keep being used as a conntrack map key. Populated alongside Packet by
// newPacket.
//
// Fields are interpreted based on Packet.Protocol:
//   - ProtoTCP: TCPFlags is meaningful; ICMPType / ICMPCode are zero
//   - ProtoICMP, ProtoICMPv6: ICMPType / ICMPCode are meaningful; TCPFlags is zero
//   - ProtoUDP and others: only Length is meaningful
type PacketContext struct {
	// Length is the total IP packet length in bytes, including headers.
	Length uint16
	// TCPFlags is the flag byte from the TCP header (bits for FIN, SYN, RST,
	// PSH, ACK, URG, ECE, CWR).
	TCPFlags uint8
	// ICMPType is the type field of the ICMP / ICMPv6 header.
	ICMPType uint8
	// ICMPCode is the code field of the ICMP / ICMPv6 header.
	ICMPCode uint8
}

func (fp *Packet) Copy() *Packet {
	return &Packet{
		LocalAddr:  fp.LocalAddr,
		RemoteAddr: fp.RemoteAddr,
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
	case ProtoICMPv6:
		proto = "icmpv6"
	case ProtoUDP:
		proto = "udp"
	default:
		proto = fmt.Sprintf("unknown %v", fp.Protocol)
	}
	return json.Marshal(m{
		"LocalAddr":  fp.LocalAddr.String(),
		"RemoteAddr": fp.RemoteAddr.String(),
		"LocalPort":  fp.LocalPort,
		"RemotePort": fp.RemotePort,
		"Protocol":   proto,
		"Fragment":   fp.Fragment,
	})
}
