//go:build !e2e_testing
// +build !e2e_testing

package udp

import "log/slog"

// wrapWithWDFBypass is a no-op on windows-386 since we don't currently build for it.
func wrapWithWDFBypass(_ *slog.Logger, conn Conn) Conn {
	return conn
}
