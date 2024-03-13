package nebula

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func configLogger(l *logrus.Logger, c *config.C) error {
	// set up our logging level
	logLevel, err := logrus.ParseLevel(strings.ToLower(c.GetString("logging.level").UnwrapOr("info")))
	if err != nil {
		return fmt.Errorf("%s; possible levels: %s", err, logrus.AllLevels)
	}
	l.SetLevel(logLevel)

	disableTimestamp := c.GetBool("logging.disable_timestamp").UnwrapOr(false)
	timestampFormat := c.GetString("logging.timestamp_format").UnwrapOrDefault()
	fullTimestamp := (timestampFormat != "")
	if timestampFormat == "" {
		timestampFormat = time.RFC3339
	}

	logFormat := strings.ToLower(c.GetString("logging.format").UnwrapOr("text"))
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
