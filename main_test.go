package nebula

import (
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

func NewTestLogger() *logrus.Logger {
	l := logrus.New()

	v := os.Getenv("TEST_LOGS")
	if v == "" {
		l.SetOutput(ioutil.Discard)
		return l
	}

	switch v {
	case "1":
		// This is the default level but we are being explicit
		l.SetLevel(logrus.InfoLevel)
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	}

	return l
}
