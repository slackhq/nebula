//go:build !e2e_testing

package overlay

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var tcpipInterfaceKeys = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
}

// disableDNSRegistration prevents publishing overlay addresses in the host's
// DNS records, where clients outside the overlay cannot reach them.
// Failures are non-fatal so registry access cannot prevent tunnel creation.
func disableDNSRegistration(l *slog.Logger, guid windows.GUID) {
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
	// The stack may not have created the adapter's interface key yet.
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKLM\\%s: %w", path, err)
	}
	defer k.Close()

	// Neither RegistrationEnabled nor DisableDynamicUpdate alone reliably
	// prevents registration, so all three settings are required.
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
