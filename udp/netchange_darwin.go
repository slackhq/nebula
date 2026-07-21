//go:build darwin && !ios && !e2e_testing
// +build darwin,!ios,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// netChangeSettleWindow is how long we keep swallowing routing messages after the first interesting one. A
	// single network change is never a single message, it is a burst: the link drops, addresses go away, new ones
	// arrive, routes get rewritten. Reporting part way through that just means reporting again.
	netChangeSettleWindow = time.Second

	// netChangeReadBuffer is sized well past any rt_msghdr plus its addresses. A short read would be discarded by
	// the kernel, so being generous here is how we avoid missing a message.
	netChangeReadBuffer = 4096
)

// WatchNetworkChanges reports when the local network moves out from under us, so the listener can be rebound.
//
// Darwin scopes a udp socket to whatever interface it came up on. Move between networks and we keep sending out an
// interface that no longer has a route, which surfaces as an instant "no route to host" with no packet ever leaving
// the box. Rebind clears that, but only if something notices the change and calls it. iOS has always been told by
// the host app off NWPathMonitor. This is the equivalent for everything else that runs on darwin.
//
// The returned channel is buffered and coalescing: a send is dropped if one is already pending, since both mean the
// same thing to a reader. It is closed when ctx is cancelled or the routing socket fails, so a caller can simply
// range over it. Platforms whose sockets do not need rebinding return a nil channel and no error.
func WatchNetworkChanges(ctx context.Context, l *slog.Logger) (<-chan struct{}, error) {
	sock, err := openRouteSocket()
	if err != nil {
		return nil, err
	}

	changes := make(chan struct{}, 1)

	go func() {
		defer close(changes)
		defer func() { _ = sock.Close() }()

		// Closing the socket is what unblocks the read in watchRouteSocket, so this turns cancellation into a
		// close. It is scoped to this call so it cannot outlive the watch it belongs to.
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				_ = sock.Close()
			case <-done:
			}
		}()

		watchRouteSocket(l, sock, changes)
	}()

	return changes, nil
}

// watchRouteSocket blocks reading the routing socket, reporting once per settled burst of changes. It returns when
// the socket is closed, which is how cancellation gets us out of here.
func watchRouteSocket(l *slog.Logger, sock *os.File, changes chan<- struct{}) {
	buf := make([]byte, netChangeReadBuffer)

	for {
		n, err := sock.Read(buf)
		if err != nil {
			logRouteSocketError(l, err)
			return
		}

		if !isNetworkChange(buf[:n]) {
			continue
		}

		// Swallow the rest of the burst. The deadline is absolute and not extended by what arrives, so this always
		// ends after the settle window no matter how chatty the socket is. Changes that land after the window
		// simply produce another report, which is the correct outcome anyway.
		deadline := time.Now().Add(netChangeSettleWindow)
		for {
			if err = sock.SetReadDeadline(deadline); err != nil {
				logRouteSocketError(l, err)
				return
			}

			if _, err = sock.Read(buf); err != nil {
				if os.IsTimeout(err) {
					break
				}
				logRouteSocketError(l, err)
				return
			}
		}

		if err = sock.SetReadDeadline(time.Time{}); err != nil {
			logRouteSocketError(l, err)
			return
		}

		select {
		case changes <- struct{}{}:
		default:
			// One already pending, and a second "the network moved" tells the reader nothing new.
		}
	}
}

// logRouteSocketError reports a routing socket failure unless it is just us shutting the socket down.
func logRouteSocketError(l *slog.Logger, err error) {
	if errors.Is(err, os.ErrClosed) {
		return
	}

	l.Error("Error reading the routing socket, will no longer notice local network changes", "error", err)
}

// openRouteSocket returns the routing socket as a non blocking os.File. Going through os.File puts reads on the go
// poller, which buys us both a working read deadline and a Close that unblocks a read in progress.
func openRouteSocket() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return os.NewFile(uintptr(fd), "route"), nil
}

// isNetworkChange reports whether a routing message means our local addressing may have moved out from under us.
//
// We read the header instead of parsing the message because the type is the only part we need, and a full parse can
// fail on shapes we don't care about, which would turn "a message I can't parse" into "a change I missed".
// rt_msghdr, if_msghdr and ifa_msghdr all begin with the same three fields, so this is the same for every type.
func isNetworkChange(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}

	// u_short msglen, u_char version, u_char type
	if int(binary.NativeEndian.Uint16(msg[0:2])) > len(msg) || msg[2] != unix.RTM_VERSION {
		return false
	}

	switch msg[3] {
	case unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO:
		// An address arrived or left, or a link changed state. Anything else on this socket is either a route
		// churning underneath us, which a rebind doesn't help with, or unrelated traffic.
		return true
	default:
		return false
	}
}
