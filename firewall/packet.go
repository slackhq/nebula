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

// PacketKey is the firewall's conntrack and ConntrackCache map key — the
// dense form of the 5-tuple plus the protocol and fragment flag the
// firewall actually discriminates flows on. Kept separate from Packet so
// the conntrack-hit fast path doesn't pay for hashing the unique.Handle
// each netip.Addr carries, and so the inbound parser can skip the
// AddrFrom4/AddrFrom16 calls until rule matching actually needs them.
//
// Superset of the coalescer's flowKey shape (same 5-tuple, just in
// Local/Remote orientation rather than wire src/dst).
type PacketKey struct {
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	LocalPort  uint16
	RemotePort uint16
	IsV6       bool
	Protocol   uint8
	Fragment   bool
}

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

// Key derives a PacketKey from a populated Packet. Used by the outgoing
// path (inside.go) which still parses into a full Packet via newPacket
// before the firewall check; the inbound path skips this hop entirely by
// having its parser write straight into the PacketKey.
func (fp *Packet) Key() PacketKey {
	k := PacketKey{
		Protocol: fp.Protocol,
		Fragment: fp.Fragment,
	}
	k.LocalPort = fp.LocalPort
	k.RemotePort = fp.RemotePort
	k.IsV6 = !fp.LocalAddr.Is4()
	if k.IsV6 {
		k.LocalAddr = fp.LocalAddr.As16()
		k.RemoteAddr = fp.RemoteAddr.As16()
	} else {
		v4 := fp.LocalAddr.As4()
		copy(k.LocalAddr[:4], v4[:])
		v4 = fp.RemoteAddr.As4()
		copy(k.RemoteAddr[:4], v4[:])
	}
	return k
}

// Hydrate fills fp's netip.Addr fields and copies the rest from k. Called
// by the firewall slow path when conntrack misses and rule matching needs
// the rich Packet form (CIDR lookups, family checks). The fast path skips
// this entirely.
func (k *PacketKey) Hydrate(fp *Packet) {
	fp.LocalPort = k.LocalPort
	fp.RemotePort = k.RemotePort
	fp.Protocol = k.Protocol
	fp.Fragment = k.Fragment
	if k.IsV6 {
		fp.LocalAddr = netip.AddrFrom16(k.LocalAddr)
		fp.RemoteAddr = netip.AddrFrom16(k.RemoteAddr)
	} else {
		var v4 [4]byte
		copy(v4[:], k.LocalAddr[:4])
		fp.LocalAddr = netip.AddrFrom4(v4)
		copy(v4[:], k.RemoteAddr[:4])
		fp.RemoteAddr = netip.AddrFrom4(v4)
	}
}

func (k *PacketKey) GetRemoteAddr() netip.Addr {
	if k.IsV6 {
		return netip.AddrFrom16(k.RemoteAddr)
	} else {
		var v4 [4]byte
		copy(v4[:], k.RemoteAddr[:4])
		return netip.AddrFrom4(v4)
	}
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
