package main

import (
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// SdNotifyReady tells systemd the service is ready and dependent services can now be started
// https://www.freedesktop.org/software/systemd/man/sd_notify.html
// https://www.freedesktop.org/software/systemd/man/systemd.service.html
const SdNotifyReady = "READY=1"

func notifyReady(l *logrus.Logger) {
	sockName := os.Getenv("NOTIFY_SOCKET")
	if sockName == "" {
		l.Debugln("NOTIFY_SOCKET systemd env var not set, not sending ready signal")
		return
	}

	conn, err := net.DialTimeout("unixgram", sockName, time.Second)
	if err != nil {
		l.WithError(err).Error("failed to connect to systemd notification socket")
		return
	}
	defer conn.Close()

	err = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		l.WithError(err).Error("failed to set the write deadline for the systemd notification socket")
		return
	}

	if _, err = conn.Write([]byte(SdNotifyReady)); err != nil {
		l.WithError(err).Error("failed to signal the systemd notification socket")
		return
	}

	l.Debugln("notified systemd the service is ready")
}
