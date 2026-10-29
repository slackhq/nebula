package udp

import (
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"net/netip"

	"github.com/slackhq/nebula/config"
)

type SendPortGetter interface {
	// UDPSendPort returns the port index to use, from [0, maxPort)
	UDPSendPort(maxPort int) uint16
}

type randomSendPort struct{}

func (randomSendPort) UDPSendPort(maxPort int) uint16 {
	return uint16(mathrand.Intn(maxPort))
}

var RandomSendPort = randomSendPort{}

// MultiPortConn holds the extra UDP sockets used to send from multiple source
// ports. Port index 0 is the base port, which is served by the caller's main
// listener. Port index i (i > 0) is served by a socket bound to basePort+i.
type MultiPortConn struct {
	conns []Conn
}

// NewMultiPortConn opens ports-1 additional UDP sockets bound to ip on
// basePort+1 through basePort+ports-1. These sockets are only used to send,
// nebula never reads from them.
func NewMultiPortConn(l *slog.Logger, ip netip.Addr, basePort uint16, ports int) (*MultiPortConn, error) {
	if ports < 1 {
		return nil, fmt.Errorf("multiport tx_ports must be at least 1, got %d", ports)
	}
	if int(basePort)+ports-1 > 65535 {
		return nil, fmt.Errorf("multiport tx_ports %d from base port %d exceeds 65535", ports, basePort)
	}

	m := &MultiPortConn{conns: make([]Conn, 0, ports-1)}
	for i := 1; i < ports; i++ {
		c, err := NewListener(l, ip, int(basePort)+i, false, 1)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("failed to open multiport socket on port %d: %w", int(basePort)+i, err)
		}
		m.conns = append(m.conns, c)
	}

	return m, nil
}

// Ports returns the total number of send ports, including the base port.
func (m *MultiPortConn) Ports() int {
	return len(m.conns) + 1
}

// WriteTo sends b to addr from the source port at index port. Index 0 (and
// any index out of range) is sent via base.
func (m *MultiPortConn) WriteTo(b []byte, port uint16, addr netip.AddrPort, base Conn) error {
	if port == 0 || int(port) > len(m.conns) {
		return base.WriteTo(b, addr)
	}
	return m.conns[port-1].WriteTo(b, addr)
}

func (m *MultiPortConn) ReloadConfig(c *config.C) {
	for _, conn := range m.conns {
		conn.ReloadConfig(c)
	}
}

func (m *MultiPortConn) Close() error {
	var errs []error
	for _, conn := range m.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
