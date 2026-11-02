package udp

import (
	"context"
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
//
// Like the main listeners, every queue gets its own socket per port, so queues never contend on one socket's
// lock or send buffer.
type MultiPortConn struct {
	// conns[q][i-1] is queue q's socket for port index i
	conns [][]Conn
	ports int
}

// NewMultiPortConn opens ports-1 additional UDP sockets per queue, bound to base.Listen's address on base.Listen's
// port + 1 through port + ports-1, with base's offload setting. With more than one queue each port is bound with
// SO_REUSEPORT, once per queue. These sockets are only used to send, nebula never reads from them, so they are
// opened SendOnly.
func NewMultiPortConn(l *slog.Logger, base Settings, ports, queues int) (*MultiPortConn, error) {
	basePort := int(base.Listen.Port())
	if ports < 1 {
		return nil, fmt.Errorf("multiport tx_ports must be at least 1, got %d", ports)
	}
	if basePort+ports-1 > 65535 {
		return nil, fmt.Errorf("multiport tx_ports %d from base port %d exceeds 65535", ports, basePort)
	}
	if queues < 1 {
		return nil, fmt.Errorf("multiport needs at least 1 queue, got %d", queues)
	}

	// Each socket logs what the main listener already logged for the same settings, keep that out of info
	quiet := sendOnlyLogger(l)
	m := &MultiPortConn{conns: make([][]Conn, queues), ports: ports}
	for q := range m.conns {
		m.conns[q] = make([]Conn, 0, ports-1)
		for i := 1; i < ports; i++ {
			port := basePort + i
			c, err := NewListener(quiet, Settings{
				Listen:   netip.AddrPortFrom(base.Listen.Addr(), uint16(port)),
				Multi:    queues > 1,
				Batch:    1,
				Offloads: base.Offloads,
				SendOnly: true,
			})
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("failed to open multiport socket on port %d for queue %d: %w", port, q, err)
			}
			m.conns[q] = append(m.conns[q], c)
		}
	}

	return m, nil
}

// Ports returns the total number of send ports, including the base port.
func (m *MultiPortConn) Ports() int {
	return m.ports
}

// Conn returns queue q's socket for the source port at index port. Index 0 (and any index or queue out of range) is
// base, the caller's main listener for q.
func (m *MultiPortConn) Conn(port uint16, q int, base Conn) Conn {
	if port == 0 || int(port) >= m.ports || q < 0 || q >= len(m.conns) {
		return base
	}
	return m.conns[q][port-1]
}

func (m *MultiPortConn) ReloadConfig(c *config.C, r *config.Reload) {
	for _, conns := range m.conns {
		for _, conn := range conns {
			conn.ReloadConfig(c, r)
		}
	}
}

func (m *MultiPortConn) Close() error {
	var errs []error
	for _, conns := range m.conns {
		for _, conn := range conns {
			if err := conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// sendOnlyLogger returns l with every record below error logged at debug instead. The multiport send sockets would
// otherwise each repeat the main listener's setup and reload logs, routines * (tx_ports - 1) times.
func sendOnlyLogger(l *slog.Logger) *slog.Logger {
	return slog.New(sendOnlyHandler{l.Handler()})
}

type sendOnlyHandler struct {
	slog.Handler
}

func sendOnlyLevel(level slog.Level) slog.Level {
	if level < slog.LevelError {
		return min(level, slog.LevelDebug)
	}
	return level
}

func (h sendOnlyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Handler.Enabled(ctx, sendOnlyLevel(level))
}

func (h sendOnlyHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Level = sendOnlyLevel(r.Level)
	return h.Handler.Handle(ctx, r)
}

func (h sendOnlyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return sendOnlyHandler{h.Handler.WithAttrs(attrs)}
}

func (h sendOnlyHandler) WithGroup(name string) slog.Handler {
	return sendOnlyHandler{h.Handler.WithGroup(name)}
}
