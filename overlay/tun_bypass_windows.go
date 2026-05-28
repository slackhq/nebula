//go:build (amd64 || arm64) && !e2e_testing
// +build amd64 arm64
// +build !e2e_testing

package overlay

import (
	"log/slog"

	"github.com/slackhq/nebula/wfp"
)

// installInterfaceBypass installs a WFP PERMIT filter scoped to the wintun interface LUID so inbound traffic on the
// nebula adapter bypasses Windows Defender Firewall.
func installInterfaceBypass(l *slog.Logger, luid uint64) closer {
	s, err := wfp.PermitInterface(luid)
	if err != nil {
		l.Warn("Failed to install WFP bypass filters on nebula interface", "error", err)
		return nil
	}
	l.Info("Installed WFP filters bypassing Windows Defender Firewall on nebula interface")
	return s
}
