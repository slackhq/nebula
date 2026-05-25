//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"log/slog"
	"net/netip"
)

// NewListenerSelector chooses between the io_uring-backed Conn and the
// recvmmsg-based Conn at runtime. The io_uring branch is taken only when
// the caller asks for it AND the running kernel advertises the required
// IORING_OP_RECVMSG / IORING_OP_SENDMSG opcodes — otherwise we warn and
// fall through to NewListener so a misconfigured deployment still works.
//
// opts carries the io_uring tunables (ring sizes, slot counts). They are
// validated and normalized inside NewIoUringListener, so an operator
// setting a bad value gets a log warning rather than a startup failure.
func NewListenerSelector(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int, opts IoUringOptions) (Conn, error) {
	if opts.Enabled {
		if IoUringAvailable() {
			return NewIoUringListener(l, ip, port, multi, batch, opts)
		}
		l.Warn("listen.io_uring set but kernel does not advertise required io_uring ops; falling back to recvmmsg path")
	}
	return NewListener(l, ip, port, multi, batch)
}
