package nebula

import (
	"fmt"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
)

type disabledTun struct {
	block  chan struct{}
	cidr   *net.IPNet
	logger *log.Logger
}

func newDisabledTun(cidr *net.IPNet, l *log.Logger) *disabledTun {
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
	t.logger.WithField("raw", prettyPacket(b)).Debugf("Disabled tun received unexpected payload")
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
