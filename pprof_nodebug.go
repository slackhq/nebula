//go:build !debug

package nebula

import (
	"context"
	"log/slog"
)

// startPprofServer is a no-op unless built with `-tags debug` (see make debug).
func startPprofServer(_ context.Context, _ *slog.Logger) {}
