package main

import (
	"log/slog"
	"net"
	"os"
	"time"
)

// SdNotifyReady tells systemd the service is ready and dependent services can now be started
// https://www.freedesktop.org/software/systemd/man/sd_notify.html
// https://www.freedesktop.org/software/systemd/man/systemd.service.html
const SdNotifyReady = "READY=1"

func notifyReady(l *slog.Logger) {
	sockName := os.Getenv("NOTIFY_SOCKET")
	if sockName == "" {
		l.Debug("NOTIFY_SOCKET systemd env var not set, not sending ready signal")
		return
	}

	conn, err := net.DialTimeout("unixgram", sockName, time.Second)
	if err != nil {
		l.Error("failed to connect to systemd notification socket", "error", err)
		return
	}
	defer conn.Close()

	err = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		l.Error("failed to set the write deadline for the systemd notification socket", "error", err)
		return
	}

	if _, err = conn.Write([]byte(SdNotifyReady)); err != nil {
		l.Error("failed to signal the systemd notification socket", "error", err)
		return
	}

	l.Debug("notified systemd the service is ready")
}
