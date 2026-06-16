package iputil

import (
	"encoding/binary"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// MaxIPv4RejectPacketSize is the largest IPv4 reject packet:
	// - 20 byte ipv4 header
	// - 8 byte icmpv4 header
	// - 68 byte body (60 byte max orig ipv4 header + 8 byte orig icmpv4 header)
	maxIPv4RejectPacketSize = ipv4.HeaderLen + 8 + 60 + 8

	// MaxRejectPacketSize is sized for the largest possible reject packet (IPv6):
	// - 40 byte ipv6 header
	// - 8 byte icmpv6 header
	// - up to 1000 byte body (original packet, possibly truncated. We want to stay
	//   under the MTU with Nebula overhead included)
	maxIPv6RejectPacketSize = ipv6.HeaderLen + 8 + 1000

	MaxRejectPacketSize = maxIPv6RejectPacketSize
)

func CreateRejectPacket(packet []byte, out []byte) []byte {
	if len(packet) < 1 {
		return nil
	}

	version := int(packet[0] >> 4)
	switch version {
	case ipv4.Version:
		if len(packet) < ipv4.HeaderLen {
			return nil
		}
		// Do not send reject packets for non-first fragments
		if packet[6]&0x1f != 0 || packet[7] != 0 {
			return nil
		}
		switch packet[9] {
		case 6: // tcp
			return ipv4CreateRejectTCPPacket(packet, out)
		default:
			return ipv4CreateRejectICMPPacket(packet, out)
		}
	case ipv6.Version:
		if len(packet) < ipv6.HeaderLen {
			return nil
		}
		return ipv6CreateRejectPacket(packet, out)
	default:
		return nil
	}
}

func ipv4CreateRejectICMPPacket(packet []byte, out []byte) []byte {
	ihl := int(packet[0]&0x0f) << 2

	if len(packet) < ihl {
		// We need at least this many bytes for this to be a valid packet
		return nil
	}

	// Do not generate ICMP errors in response to ICMP error packets
	if packet[9] == 1 && len(packet) > ihl {
		icmpType := packet[ihl]
		if icmpType == 3 || icmpType == 4 || icmpType == 5 || icmpType == 11 || icmpType == 12 {
			return nil
		}
	}

	// ICMP reply includes original header and first 8 bytes of the packet
	packetLen := min(len(packet), ihl+8)

	outLen := ipv4.HeaderLen + 8 + packetLen
	if outLen > cap(out) {
		return nil
	}

	out = out[:outLen]

	ipHdr := out[0:ipv4.HeaderLen]
	ipHdr[0] = ipv4.Version<<4 | (ipv4.HeaderLen >> 2)    // version, ihl
	ipHdr[1] = 0                                          // DSCP, ECN
	binary.BigEndian.PutUint16(ipHdr[2:], uint16(outLen)) // Total Length

	ipHdr[4] = 0  // id
	ipHdr[5] = 0  //  .
	ipHdr[6] = 0  // flags, fragment offset
	ipHdr[7] = 0  //  .
	ipHdr[8] = 64 // TTL
	ipHdr[9] = 1  // protocol (icmp)
	ipHdr[10] = 0 // checksum
	ipHdr[11] = 0 //  .

	// Swap dest / src IPs
	copy(ipHdr[12:16], packet[16:20])
	copy(ipHdr[16:20], packet[12:16])

	// Calculate checksum
	binary.BigEndian.PutUint16(ipHdr[10:], tcpipChecksum(ipHdr, 0))

	// ICMP Destination Unreachable
	icmpOut := out[ipv4.HeaderLen:]
	icmpOut[0] = 3  // type (Destination unreachable)
	icmpOut[1] = 13 // code (Communication administratively prohibited)
	icmpOut[2] = 0  // checksum
	icmpOut[3] = 0  //  .
	icmpOut[4] = 0  // unused
	icmpOut[5] = 0  //  .
	icmpOut[6] = 0  //  .
	icmpOut[7] = 0  //  .

	// Copy original IP header and first 8 bytes as body
	copy(icmpOut[8:], packet[:packetLen])

	// Calculate checksum
	binary.BigEndian.PutUint16(icmpOut[2:], tcpipChecksum(icmpOut, 0))

	return out
}

func ipv4CreateRejectTCPPacket(packet []byte, out []byte) []byte {
	const tcpLen = 20

	ihl := int(packet[0]&0x0f) << 2
	outLen := ipv4.HeaderLen + tcpLen

	if len(packet) < ihl+tcpLen {
		// We need at least this many bytes for this to be a valid packet
		return nil
	}
	if outLen > cap(out) {
		return nil
	}

	out = out[:outLen]

	ipHdr := out[0:ipv4.HeaderLen]
	ipHdr[0] = ipv4.Version<<4 | (ipv4.HeaderLen >> 2)    // version, ihl
	ipHdr[1] = 0                                          // DSCP, ECN
	binary.BigEndian.PutUint16(ipHdr[2:], uint16(outLen)) // Total Length
	ipHdr[4] = 0                                          // id
	ipHdr[5] = 0                                          //  .
	ipHdr[6] = 0                                          // flags, fragment offset
	ipHdr[7] = 0                                          //  .
	ipHdr[8] = 64                                         // TTL
	ipHdr[9] = 6                                          // protocol (tcp)
	ipHdr[10] = 0                                         // checksum
	ipHdr[11] = 0                                         //  .

	// Swap dest / src IPs
	copy(ipHdr[12:16], packet[16:20])
	copy(ipHdr[16:20], packet[12:16])

	// Calculate checksum
	binary.BigEndian.PutUint16(ipHdr[10:], tcpipChecksum(ipHdr, 0))

	// TCP RST
	tcpIn := packet[ihl:]
	var ackSeq, seq uint32
	outFlags := byte(0b00000100) // RST

	// Set seq and ackSeq based on how iptables/netfilter does it in Linux:
	// - https://github.com/torvalds/linux/blob/v5.19/net/ipv4/netfilter/nf_reject_ipv4.c#L193-L221
	inAck := tcpIn[13]&0b00010000 != 0
	if inAck {
		seq = binary.BigEndian.Uint32(tcpIn[8:])
	} else {
		inSyn := uint32((tcpIn[13] & 0b00000010) >> 1)
		inFin := uint32(tcpIn[13] & 0b00000001)
		// seq from the packet + syn + fin + tcp segment length
		ackSeq = binary.BigEndian.Uint32(tcpIn[4:]) + inSyn + inFin + uint32(len(tcpIn)) - uint32(tcpIn[12]>>4)<<2
		outFlags |= 0b00010000 // ACK
	}

	tcpOut := out[ipv4.HeaderLen:]
	// Swap dest / src ports
	copy(tcpOut[0:2], tcpIn[2:4])
	copy(tcpOut[2:4], tcpIn[0:2])
	binary.BigEndian.PutUint32(tcpOut[4:], seq)
	binary.BigEndian.PutUint32(tcpOut[8:], ackSeq)
	tcpOut[12] = (tcpLen >> 2) << 4 // data offset,  reserved,  NS
	tcpOut[13] = outFlags           // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	tcpOut[14] = 0                  // window size
	tcpOut[15] = 0                  //  .
	tcpOut[16] = 0                  // checksum
	tcpOut[17] = 0                  //  .
	tcpOut[18] = 0                  // URG Pointer
	tcpOut[19] = 0                  //  .

	// Calculate checksum
	csum := ipv4PseudoheaderChecksum(ipHdr[12:16], ipHdr[16:20], 6, tcpLen)
	binary.BigEndian.PutUint16(tcpOut[16:], tcpipChecksum(tcpOut, csum))

	return out
}

func ipv6CreateRejectPacket(packet []byte, out []byte) []byte {
	proto, offset, isFragment := ipv6FindUpperProtocol(packet)
	if isFragment {
		return nil
	}
	switch proto {
	case 6: // tcp
		return ipv6CreateRejectTCPPacket(packet, out, offset)
	default:
		return ipv6CreateRejectICMPPacket(packet, out, proto, offset)
	}
}

func ipv6CreateRejectICMPPacket(packet []byte, out []byte, proto uint8, offset int) []byte {
	// Do not generate ICMPv6 errors in response to ICMPv6 error packets
	if proto == 58 && len(packet) > offset {
		icmpType := packet[offset]
		if icmpType >= 1 && icmpType <= 4 {
			return nil
		}
	}

	// Include as much of the original packet as possible, up to 1000 bytes,
	// so the response fits comfortably within any tunnel MTU.
	packetLen := min(len(packet), 1000)

	outLen := ipv6.HeaderLen + 8 + packetLen
	if outLen > cap(out) {
		return nil
	}

	out = out[:outLen]

	// IPv6 header
	ipHdr := out[0:ipv6.HeaderLen]
	ipHdr[0] = ipv6.Version << 4 // version, traffic class (high bits)
	ipHdr[1] = 0                 // traffic class (low bits), flow label (high bits)
	ipHdr[2] = 0                 // flow label
	ipHdr[3] = 0                 // flow label

	payloadLen := uint16(outLen - ipv6.HeaderLen)
	binary.BigEndian.PutUint16(ipHdr[4:], payloadLen) // payload length
	ipHdr[6] = 58                                     // next header (ICMPv6)
	ipHdr[7] = 64                                     // hop limit

	// Swap dest / src IPs (each 16 bytes, src at 8, dst at 24)
	copy(ipHdr[8:24], packet[24:40])
	copy(ipHdr[24:40], packet[8:24])

	// ICMPv6 Destination Unreachable
	icmpOut := out[ipv6.HeaderLen:]
	icmpOut[0] = 1 // type (Destination Unreachable)
	icmpOut[1] = 1 // code (Communication with destination administratively prohibited)
	icmpOut[2] = 0 // checksum
	icmpOut[3] = 0 //  .
	icmpOut[4] = 0 // unused
	icmpOut[5] = 0 //  .
	icmpOut[6] = 0 //  .
	icmpOut[7] = 0 //  .

	copy(icmpOut[8:], packet[:packetLen])

	// ICMPv6 checksum uses a pseudo-header
	csum := ipv6PseudoheaderChecksum(ipHdr[8:24], ipHdr[24:40], 58, uint32(payloadLen))
	binary.BigEndian.PutUint16(icmpOut[2:], tcpipChecksum(icmpOut, csum))

	return out
}

func ipv6CreateRejectTCPPacket(packet []byte, out []byte, offset int) []byte {
	const tcpLen = 20

	if len(packet) < offset+tcpLen {
		return nil
	}

	outLen := ipv6.HeaderLen + tcpLen
	if outLen > cap(out) {
		return nil
	}

	out = out[:outLen]

	// IPv6 header
	ipHdr := out[0:ipv6.HeaderLen]
	ipHdr[0] = ipv6.Version << 4 // version, traffic class (high bits)
	ipHdr[1] = 0                 // traffic class (low bits), flow label (high bits)
	ipHdr[2] = 0                 // flow label
	ipHdr[3] = 0                 // flow label

	binary.BigEndian.PutUint16(ipHdr[4:], tcpLen) // payload length
	ipHdr[6] = 6                                  // next header (TCP)
	ipHdr[7] = 64                                 // hop limit

	// Swap dest / src IPs
	copy(ipHdr[8:24], packet[24:40])
	copy(ipHdr[24:40], packet[8:24])

	// TCP RST
	tcpIn := packet[offset:]
	var ackSeq, seq uint32
	outFlags := byte(0b00000100) // RST

	inAck := tcpIn[13]&0b00010000 != 0
	if inAck {
		seq = binary.BigEndian.Uint32(tcpIn[8:])
	} else {
		inSyn := uint32((tcpIn[13] & 0b00000010) >> 1)
		inFin := uint32(tcpIn[13] & 0b00000001)
		ackSeq = binary.BigEndian.Uint32(tcpIn[4:]) + inSyn + inFin + uint32(len(tcpIn)) - uint32(tcpIn[12]>>4)<<2
		outFlags |= 0b00010000 // ACK
	}

	tcpOut := out[ipv6.HeaderLen:]
	// Swap dest / src ports
	copy(tcpOut[0:2], tcpIn[2:4])
	copy(tcpOut[2:4], tcpIn[0:2])
	binary.BigEndian.PutUint32(tcpOut[4:], seq)
	binary.BigEndian.PutUint32(tcpOut[8:], ackSeq)
	tcpOut[12] = (tcpLen >> 2) << 4 // data offset, reserved, NS
	tcpOut[13] = outFlags           // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	tcpOut[14] = 0                  // window size
	tcpOut[15] = 0                  //  .
	tcpOut[16] = 0                  // checksum
	tcpOut[17] = 0                  //  .
	tcpOut[18] = 0                  // URG Pointer
	tcpOut[19] = 0                  //  .

	// Calculate checksum with IPv6 pseudo-header
	csum := ipv6PseudoheaderChecksum(ipHdr[8:24], ipHdr[24:40], 6, tcpLen)
	binary.BigEndian.PutUint16(tcpOut[16:], tcpipChecksum(tcpOut, csum))

	return out
}

func ipv6FindUpperProtocol(packet []byte) (nextHeader uint8, offset int, isFragment bool) {
	nextHeader = packet[6]
	offset = ipv6.HeaderLen

	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination
			if len(packet) < offset+2 {
				return nextHeader, offset, isFragment
			}
			nextHeader = packet[offset]
			offset += int(packet[offset+1]+1) << 3

		case 44: // Fragment
			if len(packet) < offset+8 {
				return nextHeader, offset, isFragment
			}
			if packet[offset+2] != 0 || packet[offset+3]&0xf8 != 0 {
				isFragment = true
			}
			nextHeader = packet[offset]
			offset += 8

		case 51: // AH
			if len(packet) < offset+2 {
				return nextHeader, offset, isFragment
			}
			nextHeader = packet[offset]
			offset += int(packet[offset+1]+2) << 2

		default:
			return nextHeader, offset, isFragment
		}
	}
}

func CreateICMPEchoResponse(packet, out []byte) []byte {
	if len(packet) < 1 {
		return nil
	}

	switch packet[0] >> 4 {
	case 4:
		return createICMPv4EchoResponse(packet, out)
	case 6:
		return createICMPv6EchoResponse(packet, out)
	default:
		return nil
	}
}

func createICMPv4EchoResponse(packet, out []byte) []byte {
	// Return early if this is not a simple ICMP Echo Request
	//TODO: make constants out of these
	if !(len(packet) >= 28 && len(packet) <= 9001 && packet[0] == 0x45 && packet[9] == 0x01 && packet[20] == 0x08) {
		return nil
	}

	// We don't support fragmented packets
	if packet[7] != 0 || (packet[6]&0x2F != 0) {
		return nil
	}

	out = out[:len(packet)]

	copy(out, packet)

	// Swap dest / src IPs and recalculate checksum
	ipv4 := out[0:20]
	copy(ipv4[12:16], packet[16:20])
	copy(ipv4[16:20], packet[12:16])
	ipv4[10] = 0
	ipv4[11] = 0
	binary.BigEndian.PutUint16(ipv4[10:], tcpipChecksum(ipv4, 0))

	// Change type to ICMP Echo Reply and recalculate checksum
	icmp := out[20:]
	icmp[0] = 0
	icmp[2] = 0
	icmp[3] = 0
	binary.BigEndian.PutUint16(icmp[2:], tcpipChecksum(icmp, 0))

	return out
}

func createICMPv6EchoResponse(packet, out []byte) []byte {
	// IPv6 header (40 bytes) + ICMPv6 header (8 bytes minimum)
	if len(packet) < ipv6.HeaderLen+8 || len(packet) > 9001 {
		return nil
	}

	// Next Header must be ICMPv6 (58)
	if packet[6] != 58 {
		return nil
	}

	// ICMPv6 type must be Echo Request (128)
	if packet[ipv6.HeaderLen] != 128 {
		return nil
	}

	out = out[:len(packet)]
	copy(out, packet)

	// Swap src/dst addresses (bytes 8-23 and 24-39)
	copy(out[8:24], packet[24:40])
	copy(out[24:40], packet[8:24])

	// Change ICMPv6 type to Echo Reply (129)
	icmp := out[ipv6.HeaderLen:]
	icmp[0] = 129
	icmp[2] = 0
	icmp[3] = 0

	// ICMPv6 checksum uses a pseudo-header with src, dst, length, and next header
	payloadLen := uint32(len(icmp))
	csum := ipv6PseudoheaderChecksum(out[8:24], out[24:40], 58, payloadLen)
	binary.BigEndian.PutUint16(icmp[2:], tcpipChecksum(icmp, csum))

	return out
}

// calculates the TCP/IP checksum defined in rfc1071. The passed-in
// csum is any initial checksum data that's already been computed.
//
// based on:
// - https://github.com/google/gopacket/blob/v1.1.19/layers/tcpip.go#L50-L70
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

// based on:
// - https://github.com/google/gopacket/blob/v1.1.19/layers/tcpip.go#L26-L35
func ipv4PseudoheaderChecksum(src, dst []byte, proto, length uint32) (csum uint32) {
	csum += (uint32(src[0]) + uint32(src[2])) << 8
	csum += uint32(src[1]) + uint32(src[3])
	csum += (uint32(dst[0]) + uint32(dst[2])) << 8
	csum += uint32(dst[1]) + uint32(dst[3])
	csum += proto
	csum += length & 0xffff
	csum += length >> 16
	return csum
}

// based on:
// - https://github.com/google/gopacket/blob/v1.1.19/layers/tcpip.go#L37-L48
func ipv6PseudoheaderChecksum(src, dst []byte, proto, length uint32) (csum uint32) {
	for i := 0; i < 16; i += 2 {
		csum += uint32(src[i]) << 8
		csum += uint32(src[i+1])
		csum += uint32(dst[i]) << 8
		csum += uint32(dst[i+1])
	}
	csum += proto
	csum += length & 0xffff
	csum += length >> 16
	return csum
}
