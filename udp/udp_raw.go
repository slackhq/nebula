package udp

import (
	mathrand "math/rand"
	"net/netip"
)

type SendPortGetter interface {
	// UDPSendPort returns the port to use
	UDPSendPort(maxPort int) uint16
}

type randomSendPort struct{}

func (randomSendPort) UDPSendPort(maxPort int) uint16 {
	return uint16(mathrand.Intn(maxPort))
}

var RandomSendPort = randomSendPort{}

// RawSupported reports whether (*RawConn).WriteTo can send to addr. The raw
// socket only builds IPv4 headers, so IPv6 destinations must use the normal
// UDP socket.
func RawSupported(addr netip.AddrPort) bool {
	a := addr.Addr()
	return a.Is4() || a.Is4In6()
}
