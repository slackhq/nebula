package udp

import "sync/atomic"

var disableUDPCsum atomic.Bool

// SetDisableUDPCsum controls whether IPv4 UDP sockets opt out of kernel
// checksum calculation via SO_NO_CHECK. Only applicable on platforms that
// support the option (Linux). IPv6 always keeps the checksum enabled.
func SetDisableUDPCsum(disable bool) {
	disableUDPCsum.Store(disable)
}

func udpChecksumDisabled() bool {
	return disableUDPCsum.Load()
}
