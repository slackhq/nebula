package nebula

import (
	"encoding/binary"
	"net/netip"
)

func CalculateIPv4Checksum(header []byte) uint16 {
	//todo this should be elsewhere
	headerLen := int(header[0]&0x0F) * 4

	if len(header) < headerLen {
		return 0
	}

	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		word := uint32(binary.BigEndian.Uint16(header[i : i+2]))
		sum += word
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

func recalcIPv4Checksum(data []byte) {
	data[10] = 0
	data[11] = 0
	checksum := CalculateIPv4Checksum(data)
	binary.BigEndian.PutUint16(data[10:12], checksum)
}

func CalcNewUDPChecksum(oldChecksum uint16, oldSrcIP, newSrcIP netip.Addr, oldSrcPort, newSrcPort uint16) uint16 {
	// Convert IPs to uint32
	oldIP := binary.BigEndian.Uint32(oldSrcIP.AsSlice())
	newIP := binary.BigEndian.Uint32(newSrcIP.AsSlice())

	// Start with inverted checksum
	checksum := uint32(^oldChecksum)

	// Subtract old IP (as two 16-bit words)
	checksum += uint32(^uint16(oldIP >> 16))
	checksum += uint32(^uint16(oldIP & 0xFFFF))

	// Subtract old port
	checksum += uint32(^oldSrcPort)

	// Add new IP (as two 16-bit words)
	checksum += uint32(newIP >> 16)
	checksum += uint32(newIP & 0xFFFF)

	// Add new port
	checksum += uint32(newSrcPort)

	// Fold carries
	for checksum > 0xFFFF {
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	}

	// Return ones' complement
	return ^uint16(checksum)
}

func recalcUDPv4Checksum(data []byte, oldSrcIP, newSrcIP netip.Addr, oldSrcPort, newSrcPort uint16) {
	const UDPChecksumOffset = 20 + 6 //todo pls no options pls, big bad stupid hack
	oldcsum := binary.BigEndian.Uint16(data[UDPChecksumOffset : UDPChecksumOffset+2])
	checksum := CalcNewUDPChecksum(oldcsum, oldSrcIP, newSrcIP, oldSrcPort, newSrcPort)
	binary.BigEndian.PutUint16(data[UDPChecksumOffset:UDPChecksumOffset+2], checksum)
}
