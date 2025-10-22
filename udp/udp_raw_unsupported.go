//go:build !linux || android || e2e_testing
// +build !linux android e2e_testing

package udp

import (
	"fmt"
	"net/netip"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

const RawOverhead = 0

type RawConn struct{}

func NewRawConn(l *logrus.Logger, ip string, port int, basePort uint16) (*RawConn, error) {
	return nil, fmt.Errorf("multiport tx is not supported on %s", runtime.GOOS)
}

func (u *RawConn) WriteTo(raw []byte, fromPort uint16, addr netip.AddrPort) error {
	return fmt.Errorf("multiport tx is not supported on %s", runtime.GOOS)
}

func (u *RawConn) ReloadConfig(c *config.C) {}

func NewRawStatsEmitter(rawConn *RawConn) func() { return func() {} }
