package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/routing"
)

type disabledTun struct {
	read        chan []byte
	vpnNetworks []netip.Prefix

	// Track these metrics since we don't have the tun device to do it for us
	tx metrics.Counter
	rx metrics.Counter
	l  *logrus.Logger
}

func newDisabledTun(vpnNetworks []netip.Prefix, queueLen int, metricsEnabled bool, l *logrus.Logger) *disabledTun {
	tun := &disabledTun{
		vpnNetworks: vpnNetworks,
		read:        make(chan []byte, queueLen),
		l:           l,
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

func (t *disabledTun) Read(b []byte) (int, error) {
	r, ok := <-t.read
	if !ok {
		return 0, io.EOF
	}

	if len(r) > len(b) {
		return 0, fmt.Errorf("packet larger than mtu: %d > %d bytes", len(r), len(b))
	}

	t.tx.Inc(1)
	if t.l.Level >= logrus.DebugLevel {
		t.l.WithField("raw", prettyPacket(r)).Debugf("Write payload")
	}

	return copy(b, r), nil
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
		t.l.Debugf("tun_disabled: dropped ICMP Echo Reply response")
	}

	return true
}

func (t *disabledTun) Write(b []byte) (int, error) {
	t.rx.Inc(1)

	// Check for ICMP Echo Request before spending time doing the full parsing
	if t.handleICMPEchoRequest(b) {
		if t.l.Level >= logrus.DebugLevel {
			t.l.WithField("raw", prettyPacket(b)).Debugf("Disabled tun responded to ICMP Echo Request")
		}
	} else if t.l.Level >= logrus.DebugLevel {
		t.l.WithField("raw", prettyPacket(b)).Debugf("Disabled tun received unexpected payload")
	}
	return len(b), nil
}

func (t *disabledTun) NewMultiQueueReader() (BatchReadWriter, error) {
	return t, nil
}

// BatchRead reads a single packet (batch size 1 for disabled tun)
func (t *disabledTun) BatchRead(bufs [][]byte, sizes []int) (int, error) {
	n, err := t.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// WriteBatch writes packets individually (no batching for disabled tun)
func (t *disabledTun) WriteBatch(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		_, err := t.Write(buf[offset:])
		if err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// BatchSize returns 1 for disabled tun (no batching)
func (t *disabledTun) BatchSize() int {
	return 1
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
