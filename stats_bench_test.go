package nebula

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/slackhq/nebula/config"
)

func BenchmarkLoadStatsConfig(b *testing.B) {
	for _, overridden := range []bool{false, true} {
		name := "defaults"
		if overridden {
			name = "overrides"
		}
		b.Run(name, func(b *testing.B) {
			conf := config.NewC(slog.New(slog.DiscardHandler))
			settings := map[string]any{
				"type": "prometheus", "interval": "10s",
				"listen": "127.0.0.1:0", "path": "/metrics",
			}
			if overridden {
				settings["read_header_timeout"] = "1s"
				settings["read_timeout"] = "2s"
				settings["write_timeout"] = "3s"
				settings["idle_timeout"] = "4s"
			}
			conf.Settings["stats"] = settings
			b.ReportAllocs()
			for b.Loop() {
				if _, err := loadStatsConfig(conf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Measure the real metrics handler after priming the registry. This includes
// response recording, but excludes TCP and startup so both revisions use the
// same harness when comparing scrape allocations and CPU cost.
func BenchmarkStatsPrometheusScrape(b *testing.B) {
	logger := slog.New(slog.DiscardHandler)
	conf := config.NewC(logger)
	conf.Settings["stats"] = map[string]any{
		"type": "prometheus", "interval": "10s",
		"listen": "127.0.0.1:0", "path": "/metrics",
	}
	cfg, err := loadStatsConfig(conf)
	if err != nil {
		b.Fatal(err)
	}
	server := &statsServer{l: logger, ctx: b.Context()}
	capture, listener := server.buildRuntime(b.Context(), cfg)
	for _, fn := range capture {
		fn()
	}
	request := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/metrics", nil)
	b.ReportAllocs()
	for b.Loop() {
		response := httptest.NewRecorder()
		listener.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			b.Fatalf("scrape status = %d", response.Code)
		}
	}
}
