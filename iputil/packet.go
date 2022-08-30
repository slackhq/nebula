package iputil

import (
	"encoding/binary"

	"golang.org/x/net/ipv4"
)

func CreateRejectPacket(packet []byte, out []byte) []byte {
	// TODO ipv4 only, need to fix when inside supports ipv6
	switch packet[9] {
	case 6: // tcp
		return ipv4CreateRejectTCPPacket(packet, out)
	default:
		return ipv4CreateRejectICMPPacket(packet, out)
	}
}

func ipv4CreateRejectICMPPacket(packet []byte, out []byte) []byte {
	ihl := int(packet[0]&0x0f) << 2

	// ICMP reply includes header and first 8 bytes of the packet
	packetLen := len(packet)
	if packetLen > ihl+8 {
		packetLen = ihl + 8
	}

	outLen := ipv4.HeaderLen + 8 + packetLen

	out = out[:(outLen)]

	ipHdr := out[0:ipv4.HeaderLen]
	ipHdr[0] = ipv4.Version<<4 | (ipv4.HeaderLen >> 2)                        // version, ihl
	ipHdr[1] = 0                                                              // DSCP, ECN
	binary.BigEndian.PutUint16(ipHdr[2:], uint16(ipv4.HeaderLen+8+packetLen)) // Total Length

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
	icmpOut[0] = 3 // type (Destination unreachable)
	icmpOut[1] = 3 // code (Port unreachable error)
	icmpOut[2] = 0 // checksum
	icmpOut[3] = 0 //  .
	icmpOut[4] = 0 // unused
	icmpOut[5] = 0 //  .
	icmpOut[6] = 0 //  .
	icmpOut[7] = 0 //  .

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

	out = out[:(outLen)]

	ipHdr := out[0:ipv4.HeaderLen]
	ipHdr[0] = ipv4.Version<<4 | (ipv4.HeaderLen >> 2)               // version, ihl
	ipHdr[1] = 0                                                     // DSCP, ECN
	binary.BigEndian.PutUint16(ipHdr[2:], uint16(ipv4.HeaderLen+20)) // Total Length
	ipHdr[4] = 0                                                     // id
	ipHdr[5] = 0                                                     //  .
	ipHdr[6] = 0                                                     // flags, fragment offset
	ipHdr[7] = 0                                                     //  .
	ipHdr[8] = 64                                                    // TTL
	ipHdr[9] = 6                                                     // protocol (tcp)
	ipHdr[10] = 0                                                    // checksum
	ipHdr[11] = 0                                                    //  .

	// Swap dest / src IPs
	copy(ipHdr[12:16], packet[16:20])
	copy(ipHdr[16:20], packet[12:16])

	// Calculate checksum
	binary.BigEndian.PutUint16(ipHdr[10:], tcpipChecksum(ipHdr, 0))

	// TCP RST
	tcpIn := packet[ihl:]
	tcpOut := out[ipv4.HeaderLen:]
	seq := binary.BigEndian.Uint32(tcpIn[4:]) + 1
	// Swap dest / src ports
	copy(tcpOut[0:2], tcpIn[2:4])
	copy(tcpOut[2:4], tcpIn[0:2])
	binary.BigEndian.PutUint32(tcpOut[4:], seq)
	binary.BigEndian.PutUint32(tcpOut[8:], seq)
	tcpOut[12] = 5 << 4     // data offset,  reserved,  NS
	tcpOut[13] = 0b00010100 // CWR, ECE, URG, **ACK**, PSH, **RST**, SYN, FIN
	tcpOut[14] = 0          // window size
	tcpOut[15] = 0          //  .
	tcpOut[16] = 0          // checksum
	tcpOut[17] = 0          //  .
	tcpOut[18] = 0          // URG Pointer
	tcpOut[19] = 0          //  .

	// Calculate checksum
	csum := ipv4PseudoheaderChecksum(ipHdr[12:16], ipHdr[16:20], 6, tcpLen)
	binary.BigEndian.PutUint16(tcpOut[16:], tcpipChecksum(tcpOut, csum))

	return out
}

func CreateICMPEchoResponse(packet, out []byte) []byte {
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

// Checksum calculates the TCP/IP checksum defined in rfc1071. The passed-in
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
