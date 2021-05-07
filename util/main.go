package util

import (
	"io/ioutil"
	"net"
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
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	default:
		l.SetLevel(logrus.InfoLevel)
	}

	return l
}

func GetCIDR(s string) *net.IPNet {
	_, c, _ := net.ParseCIDR(s)
	return c
}
