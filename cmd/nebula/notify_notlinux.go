//go:build !linux
// +build !linux

package main

import "log/slog"

func notifyReady(_ *slog.Logger) {
	// No init service to notify
}
