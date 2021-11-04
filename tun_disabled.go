package nebula

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

type disabledTun struct {
	read chan []byte
	cidr *net.IPNet

	// Track these metrics since we don't have the tun device to do it for us
	tx metrics.Counter
	rx metrics.Counter
	l  *logrus.Logger
}

func newDisabledTun(cidr *net.IPNet, queueLen int, metricsEnabled bool, l *logrus.Logger) *disabledTun {
	tun := &disabledTun{
		cidr: cidr,
		read: make(chan []byte, queueLen),
		l:    l,
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

func (t *disabledTun) CidrNet() *net.IPNet {
	return t.cidr
}

func (*disabledTun) DeviceName() string {
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
	// Return early if this is not a simple ICMP Echo Request
	if !(len(b) >= 28 && len(b) <= mtu && b[0] == 0x45 && b[9] == 0x01 && b[20] == 0x08) {
		return false
	}

	// We don't support fragmented packets
	if b[7] != 0 || (b[6]&0x2F != 0) {
		return false
	}

	buf := make([]byte, len(b))
	copy(buf, b)

	// Swap dest / src IPs and recalculate checksum
	ipv4 := buf[0:20]
	copy(ipv4[12:16], b[16:20])
	copy(ipv4[16:20], b[12:16])
	ipv4[10] = 0
	ipv4[11] = 0
	binary.BigEndian.PutUint16(ipv4[10:], ipChecksum(ipv4))

	// Change type to ICMP Echo Reply and recalculate checksum
	icmp := buf[20:]
	icmp[0] = 0
	icmp[2] = 0
	icmp[3] = 0
	binary.BigEndian.PutUint16(icmp[2:], ipChecksum(icmp))

	// attempt to write it, but don't block
	select {
	case t.read <- buf:
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

func (t *disabledTun) WriteRaw(b []byte) error {
	_, err := t.Write(b)
	return err
}

func (t *disabledTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return t, nil
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

func ipChecksum(b []byte) uint16 {
	var c uint32
	sz := len(b) - 1

	for i := 0; i < sz; i += 2 {
		c += uint32(b[i]) << 8
		c += uint32(b[i+1])
	}
	if sz%2 == 0 {
		c += uint32(b[sz]) << 8
	}

	for (c >> 16) > 0 {
		c = (c & 0xffff) + (c >> 16)
	}

	return ^uint16(c)
}
