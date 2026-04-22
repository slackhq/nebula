package test

import (
	"io"
	"log/slog"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/logbridge"
)

func NewLogger() *logrus.Logger {
	l := logrus.New()

	v := os.Getenv("TEST_LOGS")
	if v == "" {
		l.SetOutput(io.Discard)
		return l
	}

	switch v {
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	default:
		l.SetLevel(logrus.InfoLevel)
	}

	return l
}

// NewSlogLogger returns a *slog.Logger backed by NewLogger via logbridge.
// Used while subsystems migrate from logrus to slog so individual tests
// can flip without waiting for the test infrastructure to move.
func NewSlogLogger() *slog.Logger {
	return logbridge.FromLogrus(NewLogger())
}
