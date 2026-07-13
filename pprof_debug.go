//go:build debug

package nebula

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	_ "net/http/pprof" // registers pprof handlers on http.DefaultServeMux
)

// startPprofServer serves net/http/pprof on :6060 for the life of ctx. It is
// only compiled into debug builds (`-tags debug`, `make debug`), so a debug
// build announces itself with the Info line below.
func startPprofServer(ctx context.Context, l *slog.Logger) {
	server := &http.Server{Addr: ":6060", Handler: nil}
	l.Info("Starting pprof debug server (debug build)", "addr", server.Addr)

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Error("pprof debug server stopped", "error", err)
		}
	}()

	// Shut down the server when the context is cancelled.
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			l.Debug("Error shutting down pprof debug server", "error", err)
		}
	}()
}
