//go:build !linux || android || e2e_testing

package udp

import (
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
)

// NewWireguardListener is only available on Linux builds.
func NewWireguardListener(*logrus.Logger, netip.Addr, int, bool, int) (Conn, error) {
	return nil, fmt.Errorf("wireguard experimental UDP listener is only supported on Linux")
}
