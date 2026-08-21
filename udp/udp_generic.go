//go:build (!linux || android) && !e2e_testing && !darwin
// +build !linux android
// +build !e2e_testing
// +build !darwin

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/config"
)

type GenericConn struct {
	*net.UDPConn
	l *slog.Logger
}

var _ Conn = &GenericConn{}

func NewGenericListener(l *slog.Logger, s Settings) (Conn, error) {
	lc := NewListenConfig(s.Multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", s.Listen.String())
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &GenericConn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (u *GenericConn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := u.UDPConn.WriteToUDPAddrPort(b, addr)
	return err
}

func (u *GenericConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	// An un-sendable destination costs its own packet, never the ones behind it in the batch.
	written := 0
	for i, b := range bufs {
		if _, err := u.UDPConn.WriteToUDPAddrPort(b, addrs[i]); err == nil {
			written++
		} else {
			u.l.Debug("failed to write packet in batch", "udpAddr", addrs[i], "error", err)
		}
	}
	return written, nil
}

func (u *GenericConn) LocalAddr() (netip.AddrPort, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *GenericConn) ReloadConfig(c *config.C) {

}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *GenericConn) ListenOut(r EncReader, flush func()) error {
	buffer := make([]byte, MTU)

	var lastRecvErr time.Time

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Dampen unexpected message warns to once per minute
			if lastRecvErr.IsZero() || time.Since(lastRecvErr) > time.Minute {
				lastRecvErr = time.Now()
				u.l.Warn("unexpected udp socket receive error", "error", err)
			}
			continue
		}

		r(netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()), buffer[:n:n])
		flush()
	}
}

func (u *GenericConn) SupportsMultipleReaders() bool {
	return false
}
