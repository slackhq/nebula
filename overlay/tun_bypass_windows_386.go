//go:build !e2e_testing
// +build !e2e_testing

package overlay

import "log/slog"

// installInterfaceBypass is a no-op on windows-386 because we don't currently build for it.
func installInterfaceBypass(_ *slog.Logger, _ uint64) closer {
	return nil
}
