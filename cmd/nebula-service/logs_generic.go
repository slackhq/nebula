//go:build !windows
// +build !windows

package main

import (
	"log/slog"
	"os"

	"github.com/slackhq/nebula/logging"
)

// newPlatformLogger returns a *slog.Logger that writes to stdout. Non-Windows
// platforms have no special sink to integrate with.
func newPlatformLogger() *slog.Logger {
	return logging.NewLogger(os.Stdout)
}
