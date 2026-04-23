//go:build !windows
// +build !windows

package main

import "log/slog"

func HookLogger(l *slog.Logger) {
	// Do nothing, let the logs flow to stdout/stderr
}
