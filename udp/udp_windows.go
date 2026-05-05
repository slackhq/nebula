//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

func NewListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	if multi {
		//NOTE: Technically we can support it with RIO but it wouldn't be at the socket level
		// The udp stack would need to be reworked to hide away the implementation differences between
		// Windows and Linux
		return nil, fmt.Errorf("multiple udp listeners not supported on windows")
	}

	rc, err := NewRIOListener(l, ip, port)
	if err == nil {
		return rc, nil
	}

	l.Error("Falling back to standard udp sockets", "error", err)
	return NewGenericListener(l, ip, port, multi, batch)
}

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				// There is no way to support multiple listeners safely on Windows:
				// https://docs.microsoft.com/en-us/windows/desktop/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
				return fmt.Errorf("multiple udp listeners not supported on windows")
			}
			return nil
		},
	}
}

func (u *GenericConn) Rebind() error {
	return nil
}

// Windows IP_DONTFRAGMENT and IPV6_DONTFRAG are not exposed in the
// golang.org/x/sys/windows package. Defined locally per the values in
// ws2ipdef.h / ws2tcpip.h. These are stable Win32 constants that have not
// changed since at least Windows Vista.
const (
	winIPDontFragment = 14
	winIPv6DontFrag   = 14
)

// EnablePathMTUDiscovery sets the don't-fragment bit on outbound packets.
// Windows uses IP_DONTFRAGMENT (v4) and IPV6_DONTFRAG (v6) at IPPROTO_IP /
// IPPROTO_IPV6 respectively. Note: this only enables DF on the GenericConn
// fallback path. The RIO path (RIOConn) has its own EnablePathMTUDiscovery
// in udp_rio_windows.go and is currently a no-op pending RIO-specific work.
func (u *GenericConn) EnablePathMTUDiscovery() error {
	v4 := u.isV4Socket()
	return u.controlFD(func(fd uintptr) error {
		if v4 {
			return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, winIPDontFragment, 1)
		}
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, winIPv6DontFrag, 1)
	})
}
