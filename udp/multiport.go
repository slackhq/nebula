package udp

import (
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"net/netip"

	"github.com/slackhq/nebula/config"
)

// RandomSendPort returns a random multiport send port index, from [0, ports)
func RandomSendPort(ports int) uint16 {
	return uint16(mathrand.Intn(ports))
}

// MultiPortConn holds the extra UDP sockets used to send from multiple source
// ports. Port index 0 is the base port, which is served by the caller's main
// listener. Port index i (i > 0) is served by a socket bound to basePort+i.
type MultiPortConn struct {
	conns []Conn
}

// NewMultiPortConn opens ports-1 additional UDP sockets bound to base.Listen's address on base.Listen's port + 1
// through port + ports-1, with base's offload setting. These sockets are only used to send, nebula never reads
// from them.
func NewMultiPortConn(l *slog.Logger, base Settings, ports int) (*MultiPortConn, error) {
	basePort := int(base.Listen.Port())
	if ports < 1 {
		return nil, fmt.Errorf("multiport tx_ports must be at least 1, got %d", ports)
	}
	if basePort+ports-1 > 65535 {
		return nil, fmt.Errorf("multiport tx_ports %d from base port %d exceeds 65535", ports, basePort)
	}

	m := &MultiPortConn{conns: make([]Conn, 0, ports-1)}
	for i := 1; i < ports; i++ {
		port := basePort + i
		c, err := NewListener(l, Settings{
			Listen:   netip.AddrPortFrom(base.Listen.Addr(), uint16(port)),
			Batch:    1,
			Offloads: base.Offloads,
		})
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("failed to open multiport socket on port %d: %w", port, err)
		}
		m.conns = append(m.conns, c)
	}

	return m, nil
}

// Ports returns the total number of send ports, including the base port.
func (m *MultiPortConn) Ports() int {
	return len(m.conns) + 1
}

// Conn returns the socket for the source port at index port. Index 0 (and any index out of range) is base.
func (m *MultiPortConn) Conn(port uint16, base Conn) Conn {
	if port == 0 || int(port) > len(m.conns) {
		return base
	}
	return m.conns[port-1]
}

// WriteTo sends b to addr from the source port at index port, see Conn.
func (m *MultiPortConn) WriteTo(b []byte, port uint16, addr netip.AddrPort, base Conn) error {
	return m.Conn(port, base).WriteTo(b, addr)
}

func (m *MultiPortConn) ReloadConfig(c *config.C, r *config.Reload) {
	for _, conn := range m.conns {
		conn.ReloadConfig(c, r)
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
