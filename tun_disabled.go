package nebula

import (
	"fmt"
	"io"
	"net"
	"strings"

	"go.uber.org/zap"
)

type disabledTun struct {
	block  chan struct{}
	cidr   *net.IPNet
	logger *zap.Logger
}

func newDisabledTun(cidr *net.IPNet, l *zap.Logger) *disabledTun {
	return &disabledTun{
		cidr:   cidr,
		block:  make(chan struct{}),
		logger: l,
	}
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
	<-t.block
	return 0, io.EOF
}

func (t *disabledTun) Write(b []byte) (int, error) {
	t.logger.Debug(
		"disabled tun received unexpected payload",
		zap.Any("raw", prettyPacket(b)),
	)
	return len(b), nil
}

func (t *disabledTun) WriteRaw(b []byte) error {
	_, err := t.Write(b)
	return err
}

func (t *disabledTun) Close() error {
	if t.block != nil {
		close(t.block)
		t.block = nil
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
