package nebula

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// startHttp returns a function to start an http server with pprof support and optionally a provided stats
// http handler.
func startHttp(l *logrus.Logger, c *config.C, listen string, statsHandler statsHandlerFunc) (func(), error) {
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

	return func() {
		l.Infof("Go pprof handler listening on %s at /debug/pprof", listen)
		if statsHandler != nil {
			http.Handle(statsPath, statsHandler(listen, statsPath))
		}
		l.Fatal(http.ListenAndServe(listen, nil))
	}, nil
}
