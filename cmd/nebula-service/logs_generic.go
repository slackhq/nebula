// +build !windows

package main

import "github.com/sirupsen/logrus"

func HookLogger(l *logrus.Logger) {
	// Do nothing, let the logs flow to stdout/stderr
}
