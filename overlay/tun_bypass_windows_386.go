//go:build !e2e_testing

package overlay

import "log/slog"

// interfaceBypassKeys is empty, windows-386 has no bypass
var interfaceBypassKeys []string

// installInterfaceBypass is a no-op on windows-386 because we don't currently build for it.
func installInterfaceBypass(_ *slog.Logger, _ uint64) closer {
	return nil
}
