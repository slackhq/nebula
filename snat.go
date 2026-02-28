package nebula

import (
	"encoding/binary"
	"net/netip"
)

func recalcIPv4Checksum(data []byte, oldSrcIP netip.Addr, newSrcIP netip.Addr) {
	oldChecksum := binary.BigEndian.Uint16(data[10:12])
	//because of how checksums work, we can re-use this function
	checksum := calcNewTransportChecksum(oldChecksum, oldSrcIP, 0, newSrcIP, 0)
	binary.BigEndian.PutUint16(data[10:12], checksum)
}

func calcNewTransportChecksum(oldChecksum uint16, oldSrcIP netip.Addr, oldSrcPort uint16, newSrcIP netip.Addr, newSrcPort uint16) uint16 {
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

func recalcV4TransportChecksum(offsetInsideHeader int, data []byte, oldSrcIP netip.AddrPort, newSrcIP netip.AddrPort) {
	ipHeaderOffset := int(data[0]&0x0F) * 4
	offset := ipHeaderOffset + offsetInsideHeader
	oldcsum := binary.BigEndian.Uint16(data[offset : offset+2])
	checksum := calcNewTransportChecksum(oldcsum, oldSrcIP.Addr(), oldSrcIP.Port(), newSrcIP.Addr(), newSrcIP.Port())
	binary.BigEndian.PutUint16(data[offset:offset+2], checksum)
}

func recalcUDPv4Checksum(data []byte, oldSrcIP netip.AddrPort, newSrcIP netip.AddrPort) {
	const offsetInsideHeader = 6
	recalcV4TransportChecksum(offsetInsideHeader, data, oldSrcIP, newSrcIP)
}

func recalcTCPv4Checksum(data []byte, oldSrcIP netip.AddrPort, newSrcIP netip.AddrPort) {
	const offsetInsideHeader = 16
	recalcV4TransportChecksum(offsetInsideHeader, data, oldSrcIP, newSrcIP)
}

func calcNewICMPChecksum(oldChecksum uint16, oldCode uint16, newCode uint16, oldID uint16, newID uint16) uint16 {
	// Start with inverted checksum
	checksum := uint32(^oldChecksum)

	// Subtract old stuff
	checksum += uint32(^oldCode)
	checksum += uint32(^oldID)

	// Add new stuff
	checksum += uint32(newCode)
	checksum += uint32(newID)

	// Fold carries
	for checksum > 0xFFFF {
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	}

	// Return ones' complement
	return ^uint16(checksum)
}

func recalcICMPv4Checksum(data []byte, oldCode uint16, newCode uint16, oldID uint16, newID uint16) {
	const offsetInsideHeader = 2
	ipHeaderOffset := int(data[0]&0x0F) * 4
	offset := ipHeaderOffset + offsetInsideHeader
	oldChecksum := binary.BigEndian.Uint16(data[offset : offset+2])
	checksum := calcNewICMPChecksum(oldChecksum, oldCode, newCode, oldID, newID)
	binary.BigEndian.PutUint16(data[offset:offset+2], checksum)
}
