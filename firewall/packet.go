package firewall

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

	minFwPacketLen = 4
)

var (
	ErrPacketTooShort          = errors.New("packet is too short")
	ErrUnknownIPVersion        = errors.New("packet is an unknown ip version")
	ErrIPv4InvalidHeaderLength = errors.New("invalid ipv4 header length")
	ErrIPv4PacketTooShort      = errors.New("ipv4 packet is too short")
	ErrIPv6PacketTooShort      = errors.New("ipv6 packet is too short")
	ErrIPv6CouldNotFindPayload = errors.New("could not find payload in ipv6 packet")
)

type Packet struct {
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	LocalPort  uint16
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
		"LocalAddr":  fp.LocalAddr.String(),
		"RemoteAddr": fp.RemoteAddr.String(),
		"LocalPort":  fp.LocalPort,
		"RemotePort": fp.RemotePort,
		"Protocol":   proto,
		"Fragment":   fp.Fragment,
	})
}

func parseV6(data []byte, incoming bool, fp *Packet) error {
	dataLen := len(data)
	if dataLen < ipv6.HeaderLen {
		return ErrIPv6PacketTooShort
	}

	if incoming {
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[24:40])
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[24:40])
	}

	protoAt := 6             // NextHeader is at 6 bytes into the ipv6 header
	offset := ipv6.HeaderLen // Start at the end of the ipv6 header
	next := 0
	for {
		if protoAt >= dataLen {
			break
		}
		proto := layers.IPProtocol(data[protoAt])

		switch proto {
		case layers.IPProtocolICMPv6, layers.IPProtocolESP, layers.IPProtocolNoNextHeader:
			fp.Protocol = uint8(proto)
			fp.RemotePort = 0
			fp.LocalPort = 0
			fp.Fragment = false
			return nil

		case layers.IPProtocolTCP, layers.IPProtocolUDP:
			if dataLen < offset+4 {
				return ErrIPv6PacketTooShort
			}

			fp.Protocol = uint8(proto)
			if incoming {
				fp.RemotePort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.LocalPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			} else {
				fp.LocalPort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.RemotePort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			}

			fp.Fragment = false
			return nil

		case layers.IPProtocolIPv6Fragment:
			// Fragment header is 8 bytes, need at least offset+4 to read the offset field
			if dataLen < offset+8 {
				return ErrIPv6PacketTooShort
			}

			// Check if this is the first fragment
			fragmentOffset := binary.BigEndian.Uint16(data[offset+2:offset+4]) &^ uint16(0x7) // Remove the reserved and M flag bits
			if fragmentOffset != 0 {
				// Non-first fragment, use what we have now and stop processing
				fp.Protocol = data[offset]
				fp.Fragment = true
				fp.RemotePort = 0
				fp.LocalPort = 0
				return nil
			}

			// The next loop should be the transport layer since we are the first fragment
			next = 8 // Fragment headers are always 8 bytes

		case layers.IPProtocolAH:
			// Auth headers, used by IPSec, have a different meaning for header length
			if dataLen <= offset+1 {
				break
			}

			next = int(data[offset+1]+2) << 2

		default:
			// Normal ipv6 header length processing
			if dataLen <= offset+1 {
				break
			}

			next = int(data[offset+1]+1) << 3
		}

		if next <= 0 {
			// Safety check, each ipv6 header has to be at least 8 bytes
			next = 8
		}

		protoAt = offset
		offset = offset + next
	}

	return ErrIPv6CouldNotFindPayload
}

func parseV4(data []byte, incoming bool, fp *Packet) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return ErrIPv4PacketTooShort
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well-formed ip header length?
	if ihl < ipv4.HeaderLen {
		return ErrIPv4InvalidHeaderLength
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	fp.Fragment = (flagsfrags & 0x1FFF) != 0

	// Firewall handles protocol checks
	fp.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !fp.Fragment && fp.Protocol != ProtoICMP {
		minLen += minFwPacketLen
	}
	if len(data) < minLen {
		return ErrIPv4InvalidHeaderLength
	}

	// Firewall packets are locally oriented
	if incoming {
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[16:20])
		if fp.Fragment || fp.Protocol == ProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[16:20])
		if fp.Fragment || fp.Protocol == ProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

// NewPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func NewPacket(data []byte, incoming bool, fp *Packet) error {
	if len(data) < 1 {
		return ErrPacketTooShort
	}

	version := int((data[0] >> 4) & 0x0f)
	switch version {
	case ipv4.Version:
		return parseV4(data, incoming, fp)
	case ipv6.Version:
		return parseV6(data, incoming, fp)
	}
	return ErrUnknownIPVersion
}
