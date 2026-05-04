package checksum

//go:noescape
func checksumNEON(buf []byte, initial uint16) uint16

// Checksum computes the RFC 1071 ones-complement sum of buf, seeded with
// initial. It is a drop-in replacement for gvisor's checksum.Checksum
// that dispatches to a hand-written NEON routine. NEON is mandatory in
// armv8 so no feature check is needed.
func Checksum(buf []byte, initial uint16) uint16 {
	return checksumNEON(buf, initial)
}
