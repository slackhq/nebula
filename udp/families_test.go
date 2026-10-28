//go:build !e2e_testing

package udp

import (
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/slackhq/nebula/test"
)

func TestNewListenerCanSend(t *testing.T) {
	// The IPv6 wildcard also reaches IPv4 unless the socket has IPV6_V6ONLY set: Go clears it on its sockets, Linux
	// leaves it to the net.ipv6.bindv6only sysctl and OpenBSD always sets it
	wildcardV4 := true
	switch runtime.GOOS {
	case "linux":
		sysctl, err := os.ReadFile("/proc/sys/net/ipv6/bindv6only")
		if err != nil {
			t.Fatalf("read bindv6only: %v", err)
		}
		wildcardV4 = strings.TrimSpace(string(sysctl)) != "1"
	case "openbsd":
		wildcardV4 = false
	}

	// Go opens the IPv4 wildcard as the dual stack IPv6 wildcard where the OS has dual stack sockets. Linux opens its
	// own socket, OpenBSD has none, and Windows RIO binds the IPv4-mapped address.
	wildcardV6 := true
	switch runtime.GOOS {
	case "linux", "openbsd", "windows":
		wildcardV6 = false
	}

	for _, tc := range []struct {
		listen    string
		canSendV4 bool
		canSendV6 bool
	}{
		{"127.0.0.1:0", true, false},
		{"0.0.0.0:0", true, wildcardV6},
		{"[::1]:0", false, true},
		{"[::]:0", wildcardV4, true},
	} {
		c, err := NewListener(test.NewLogger(), Settings{Listen: netip.MustParseAddrPort(tc.listen), Batch: 1})
		if err != nil {
			t.Fatalf("NewListener %s: %v", tc.listen, err)
		}
		if got := c.CanSendIPv4(); got != tc.canSendV4 {
			t.Errorf("CanSendIPv4() on %s = %v, want %v", tc.listen, got, tc.canSendV4)
		}
		if got := c.CanSendIPv6(); got != tc.canSendV6 {
			t.Errorf("CanSendIPv6() on %s = %v, want %v", tc.listen, got, tc.canSendV6)
		}
		_ = c.Close()
	}
}
