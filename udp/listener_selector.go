//go:build !iouring || !linux || android || e2e_testing

package udp

import (
	"log/slog"
	"net/netip"
)

// NewListenerSelector returns a Conn implementation. The opts.Enabled flag
// asks for the io_uring-backed Conn; it is honored only when the binary
// is built with `-tags iouring` on Linux (non-android, non-e2e). Other
// build flavours log a warning and fall back to the platform's default
// NewListener path so a stray `listen.io_uring: true` doesn't break
// operation. opts ring-size and slot fields are ignored on this branch.
func NewListenerSelector(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int, opts IoUringOptions) (Conn, error) {
	if opts.Enabled {
		l.Warn("listen.io_uring set but io_uring path unavailable; falling back to default",
			"reason", "binary built without -tags iouring or non-linux platform")
	}
	return NewListener(l, ip, port, multi, batch)
}
