package nebula

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func startHttp(l *logrus.Logger, c *config.C, statsHandler statsHandlerFunc, listen string) (f func(), err error) {
	if listen == "" {
		return nil, nil
	}

	var statsPath string
	if statsHandler != nil {
		statsPath = c.GetString("stats.path", "")
		if statsPath == "" {
			return nil, fmt.Errorf("stats.path should not be empty")
		}
	}

	f = func() {
		l.Infof("Go pprof handler listening on %s at /debug/pprof", listen)
		if statsHandler != nil {
			http.Handle(statsPath, statsHandler(listen, statsPath))
		}
		l.Fatal(http.ListenAndServe(listen, nil))
	}

	return f, err
}
