package udp

import mathrand "math/rand"

type SendPortGetter interface {
	// UDPSendPort returns the port to use
	UDPSendPort(maxPort int) uint16
}

type randomSendPort struct{}

func (randomSendPort) UDPSendPort(maxPort int) uint16 {
	return uint16(mathrand.Intn(maxPort))
}

var RandomSendPort = randomSendPort{}
