//go:build !linux
// +build !linux

package main

import "github.com/sirupsen/logrus"

func notifyReady(_ *logrus.Logger) {
	// No init service to notify
}
