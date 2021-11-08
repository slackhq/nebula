package nebula

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type ContextualError struct {
	RealError error
	Fields    map[string]interface{}
	Context   string
}

func NewContextualError(msg string, fields map[string]interface{}, realError error) ContextualError {
	return ContextualError{Context: msg, Fields: fields, RealError: realError}
}

func (ce ContextualError) Error() string {
	if ce.RealError == nil {
		return ce.Context
	}
	return ce.RealError.Error()
}

func (ce ContextualError) Unwrap() error {
	if ce.RealError == nil {
		return errors.New(ce.Context)
	}
	return ce.RealError
}

func (ce *ContextualError) Log(lr *logrus.Logger) {
	if ce.RealError != nil {
		lr.WithFields(ce.Fields).WithError(ce.RealError).Error(ce.Context)
	} else {
		lr.WithFields(ce.Fields).Error(ce.Context)
	}
}

func configLogger(l *logrus.Logger, c *config.C) error {
	// set up our logging level
	logLevel, err := logrus.ParseLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return fmt.Errorf("%s; possible levels: %s", err, logrus.AllLevels)
	}
	l.SetLevel(logLevel)

	disableTimestamp := c.GetBool("logging.disable_timestamp", false)
	timestampFormat := c.GetString("logging.timestamp_format", "")
	fullTimestamp := (timestampFormat != "")
	if timestampFormat == "" {
		timestampFormat = time.RFC3339
	}

	logFormat := strings.ToLower(c.GetString("logging.format", "text"))
	switch logFormat {
	case "text":
		l.Formatter = &logrus.TextFormatter{
			TimestampFormat:  timestampFormat,
			FullTimestamp:    fullTimestamp,
			DisableTimestamp: disableTimestamp,
		}
	case "json":
		l.Formatter = &logrus.JSONFormatter{
			TimestampFormat:  timestampFormat,
			DisableTimestamp: disableTimestamp,
		}
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", logFormat, []string{"text", "json"})
	}

	return nil
}
