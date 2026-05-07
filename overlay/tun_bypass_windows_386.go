//go:build !e2e_testing
// +build !e2e_testing

package overlay

import "log/slog"

// installInterfaceBypass is a no-op on windows-386. WFP support relies on
// 64-bit pointer-sized struct layouts that don't translate cleanly to 32-bit,
// and windows-386 isn't a release target.
func installInterfaceBypass(_ *slog.Logger, _ uint64) closer {
	return nil
}
