//go:build !e2e_testing

package overlay

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The TCP/IP stack keeps per-adapter DNS Client settings under these keys, one
// subkey per adapter GUID and one hive per address family.
var tcpipInterfaceKeys = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
}

// disableDNSRegistration stops the Windows DNS Client from registering the
// tun adapter's addresses under the host name.
//
// On a domain-joined host the DNS Client registers every adapter that has
// "Register this connection's addresses in DNS" on, which is the default for
// a new adapter. A tun adapter that registers publishes the overlay IP as an
// A/AAAA record for the host, so LAN clients that are not on the overlay
// resolve the host to an address they cannot reach and RDP, SMB and WinRM to
// it fail intermittently. Registration happens on address assignment, on a
// timer and on every ipconfig /registerdns, so the values must be in place
// before Activate assigns addresses.
//
// RegistrationEnabled alone (the adapter checkbox) does not reliably stop
// registration, and neither does DisableDynamicUpdate alone, so all three
// values are written, matching Tailscale and NetBird.
//
// Failure is logged rather than returned: a host that cannot write these keys
// still needs its tunnel.
func disableDNSRegistration(l *slog.Logger, guid windows.GUID) {
	// GUID.String yields the braced form the Interfaces subkeys are named with.
	id := guid.String()
	for _, base := range tcpipInterfaceKeys {
		path := base + `\` + id
		if err := setDNSRegistrationValues(path); err != nil {
			l.Warn("Failed to disable DNS registration on the tun adapter", "error", err, "key", path)
			continue
		}
		l.Debug("Disabled DNS registration on the tun adapter", "key", path)
	}
}

func setDNSRegistrationValues(path string) error {
	// CreateKey opens the subkey when the stack has already created it for the
	// adapter and creates it otherwise; the values are honored either way.
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKLM\\%s: %w", path, err)
	}
	defer k.Close()

	values := []struct {
		name string
		data uint32
	}{
		{"RegistrationEnabled", 0},
		{"DisableDynamicUpdate", 1},
		{"MaxNumberOfAddressesToRegister", 0},
	}
	for _, v := range values {
		if err := k.SetDWordValue(v.name, v.data); err != nil {
			return fmt.Errorf("set %s: %w", v.name, err)
		}
	}
	return nil
}
