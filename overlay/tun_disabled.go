package overlay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/wire"
)

type disabledTun struct {
	read        chan []byte
	vpnNetworks []netip.Prefix

	// Track these metrics since we don't have the tun device to do it for us
	tx         metrics.Counter
	rx         metrics.Counter
	numReaders int
	l          *slog.Logger
}

func newDisabledTun(vpnNetworks []netip.Prefix, queueLen int, metricsEnabled bool, l *slog.Logger) *disabledTun {
	tun := &disabledTun{
		vpnNetworks: vpnNetworks,
		read:        make(chan []byte, queueLen),
		l:           l,
		numReaders:  1,
	}

	if metricsEnabled {
		tun.tx = metrics.GetOrRegisterCounter("messages.tx.message", nil)
		tun.rx = metrics.GetOrRegisterCounter("messages.rx.message", nil)
	} else {
		tun.tx = &metrics.NilCounter{}
		tun.rx = &metrics.NilCounter{}
	}

	return tun
}

func (*disabledTun) Activate() error {
	return nil
}

func (*disabledTun) RoutesFor(addr netip.Addr) routing.Gateways {
	return routing.Gateways{}
}

func (t *disabledTun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (*disabledTun) Name() string {
	return "disabled"
}

func (t *disabledTun) readOne(b []byte) (int, error) {
	r, ok := <-t.read
	if !ok {
		return 0, io.EOF
	}

	if len(r) > len(b) {
		return 0, fmt.Errorf("packet larger than mtu: %d > %d bytes", len(r), len(b))
	}

	t.tx.Inc(1)
	if t.l.Enabled(context.Background(), slog.LevelDebug) {
		t.l.Debug("Write payload", "raw", prettyPacket(r))
	}

	return copy(b, r), nil
}

func (t *disabledTun) Read(p []wire.TunPacket, mem []byte) (int, error) {
	if len(p) == 0 || len(mem) == 0 {
		return 0, nil //todo should this be an err?
	}
	p[0].Meta = wire.GSOInfo{}
	n, err := t.readOne(mem)
	if err != nil {
		return 0, err
	}
	p[0].Bytes = mem[:n]
	return 1, nil
}

func (t *disabledTun) handleICMPEchoRequest(b []byte) bool {
	out := make([]byte, len(b))
	out = iputil.CreateICMPEchoResponse(b, out)
	if out == nil {
		return false
	}

	// attempt to write it, but don't block
	select {
	case t.read <- out:
	default:
		t.l.Debug("tun_disabled: dropped ICMP Echo Reply response")
	}

	return true
}

func (t *disabledTun) Write(b []byte) (int, error) {
	t.rx.Inc(1)

	// Check for ICMP Echo Request before spending time doing the full parsing
	if t.handleICMPEchoRequest(b) {
		if t.l.Enabled(context.Background(), slog.LevelDebug) {
			t.l.Debug("Disabled tun responded to ICMP Echo Request", "raw", prettyPacket(b))
		}
	} else if t.l.Enabled(context.Background(), slog.LevelDebug) {
		t.l.Debug("Disabled tun received unexpected payload", "raw", prettyPacket(b))
	}
	return len(b), nil
}

func (t *disabledTun) SupportsMultiqueue() bool {
	return true
}

func (t *disabledTun) NewMultiQueueReader() error {
	t.numReaders++
	return nil
}

func (t *disabledTun) Readers() []tio.Queue {
	out := make([]tio.Queue, t.numReaders)
	for i := range t.numReaders {
		out[i] = t
	}
	return out
}

func (t *disabledTun) Capabilities() tio.Capabilities {
	return tio.Capabilities{}
}

func (t *disabledTun) Close() error {
	if t.read != nil {
		close(t.read)
		t.read = nil
	}
	return nil
}

type prettyPacket []byte

func (p prettyPacket) String() string {
	var s strings.Builder

	for i, b := range p {
		if i > 0 && i%8 == 0 {
			s.WriteString(" ")
		}
		s.WriteString(fmt.Sprintf("%02x ", b))
	}

	return s.String()
}
