package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/slackhq/nebula/iputil"
)

type m = map[string]any

const (
	ProtoAny     = 0  // When we want to handle HOPOPT (0) we can change this, if ever
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
	return json.Marshal(m{
		"LocalAddr":  fp.LocalAddr.String(),
		"RemoteAddr": fp.RemoteAddr.String(),
		"LocalPort":  fp.LocalPort,
		"RemotePort": fp.RemotePort,
		"Protocol":   protoName(fp.Protocol),
		"Fragment":   fp.Fragment,
	})
}

// protoNames are the protocol names that rules accept and packets report, and their numbers. Any other protocol
// is given by number.
var protoNames = []struct {
	name  string
	proto uint8
}{
	{"any", ProtoAny},
	{"tcp", iputil.IPProtocolTCP},
	{"udp", iputil.IPProtocolUDP},
	{"udplite", iputil.IPProtocolUDPLite},
	{"dccp", iputil.IPProtocolDCCP},
	{"sctp", iputil.IPProtocolSCTP},
	{"icmp", iputil.IPProtocolICMP},
	{"icmpv6", iputil.IPProtocolICMPv6},
}

// protoByName returns the number of a protocol named in protoNames.
func protoByName(name string) (uint8, bool) {
	for _, p := range protoNames {
		if p.name == name {
			return p.proto, true
		}
	}
	return 0, false
}

// protoName returns the name in protoNames of a packet's protocol, or "unknown" and its number. `any` is only
// a rule's protocol, so a packet's protocol 0 is unknown.
func protoName(proto uint8) string {
	if proto != ProtoAny {
		for _, p := range protoNames {
			if p.proto == proto {
				return p.name
			}
		}
	}
	return fmt.Sprintf("unknown %v", proto)
}

// ParsedPacket is a Packet plus the parse byproducts the RX path reuses
type ParsedPacket struct {
	Packet
	IPHdrLen int
	// FragAny reports any fragmentation at all: MF flag or nonzero offset for IPv4, a fragment extension header for IPv6.
	// Distinct from Packet.Fragment, which is true only for NON-FIRST fragments
	FragAny bool
}
