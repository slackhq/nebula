package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
)

// HookLogger routes the logrus logs through the service logger so that they end up in the Windows Event Viewer
// logrus output will be discarded
func HookLogger(l *logrus.Logger) {
	l.AddHook(newLogHook(logger))
	l.SetOutput(ioutil.Discard)
}

type logHook struct {
	sl service.Logger
}

func newLogHook(sl service.Logger) *logHook {
	return &logHook{sl: sl}
}

func (h *logHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read entry, %v", err)
		return err
	}

	switch entry.Level {
	case logrus.PanicLevel:
		return h.sl.Error(line)
	case logrus.FatalLevel:
		return h.sl.Error(line)
	case logrus.ErrorLevel:
		return h.sl.Error(line)
	case logrus.WarnLevel:
		return h.sl.Warning(line)
	case logrus.InfoLevel:
		return h.sl.Info(line)
	case logrus.DebugLevel:
		return h.sl.Info(line)
	default:
		return nil
	}
}

func (h *logHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
