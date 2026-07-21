//go:build darwin && !ios && !e2e_testing
// +build darwin,!ios,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

// routeMsg builds the first four bytes of a routing message, which is all isNetworkChange reads.
func routeMsg(msgType uint8, extra int) []byte {
	msg := make([]byte, 4+extra)
	binary.NativeEndian.PutUint16(msg[0:2], uint16(len(msg)))
	msg[2] = unix.RTM_VERSION
	msg[3] = msgType
	return msg
}

func TestIsNetworkChange(t *testing.T) {
	// The three that mean our addressing may have moved
	assert.True(t, isNetworkChange(routeMsg(unix.RTM_NEWADDR, 0)))
	assert.True(t, isNetworkChange(routeMsg(unix.RTM_DELADDR, 0)))
	assert.True(t, isNetworkChange(routeMsg(unix.RTM_IFINFO, 0)))

	// Route churn is not something a rebind helps with
	assert.False(t, isNetworkChange(routeMsg(unix.RTM_ADD, 0)))
	assert.False(t, isNetworkChange(routeMsg(unix.RTM_DELETE, 0)))
	assert.False(t, isNetworkChange(routeMsg(unix.RTM_GET, 0)))

	// Garbage must not be mistaken for a change
	assert.False(t, isNetworkChange(nil), "empty")
	assert.False(t, isNetworkChange([]byte{0, 0, 0}), "short header")

	wrongVersion := routeMsg(unix.RTM_NEWADDR, 0)
	wrongVersion[2] = unix.RTM_VERSION + 1
	assert.False(t, isNetworkChange(wrongVersion), "wrong rtm_version")

	lying := routeMsg(unix.RTM_NEWADDR, 0)
	binary.NativeEndian.PutUint16(lying[0:2], 512)
	assert.False(t, isNetworkChange(lying), "msglen longer than what we read")
}

// socketPair returns a connected pair of datagram sockets, the first wrapped the same way the routing socket is. It
// stands in for the kernel so the watch loop can be driven with synthetic messages.
func socketPair(t *testing.T) (*os.File, int) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.SetNonblock(fds[0], true))

	f := os.NewFile(uintptr(fds[0]), "route")
	t.Cleanup(func() {
		_ = f.Close()
		_ = unix.Close(fds[1])
	})

	return f, fds[1]
}

func TestWatchRouteSocketCoalescesABurst(t *testing.T) {
	sock, kernel := socketPair(t)
	changes := make(chan struct{}, 1)

	done := make(chan struct{})
	go func() {
		watchRouteSocket(test.NewLogger(), sock, changes)
		close(done)
	}()

	// One network change is a burst of messages. All of these land inside the settle window, so they must produce
	// exactly one report rather than one apiece.
	for range 5 {
		_, err := unix.Write(kernel, routeMsg(unix.RTM_NEWADDR, 8))
		require.NoError(t, err)
	}
	// Uninteresting messages in the middle of a burst must not add a report of their own either.
	_, err := unix.Write(kernel, routeMsg(unix.RTM_ADD, 8))
	require.NoError(t, err)

	select {
	case <-changes:
	case <-time.After(netChangeSettleWindow * 4):
		t.Fatal("a burst should have reported a change")
	}

	// Nothing more from that burst
	select {
	case <-changes:
		t.Fatal("a burst should report exactly once")
	case <-time.After(netChangeSettleWindow):
	}

	// A change after the window has closed is a separate event and gets its own report.
	_, err = unix.Write(kernel, routeMsg(unix.RTM_IFINFO, 8))
	require.NoError(t, err)
	select {
	case <-changes:
	case <-time.After(netChangeSettleWindow * 4):
		t.Fatal("a later change should report again")
	}

	// Closing the socket is how the real thing shuts down
	require.NoError(t, sock.Close())
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("watchRouteSocket did not return after the socket was closed")
	}
}

func TestWatchRouteSocketIgnoresUninterestingMessages(t *testing.T) {
	sock, kernel := socketPair(t)
	changes := make(chan struct{}, 1)

	done := make(chan struct{})
	go func() {
		watchRouteSocket(test.NewLogger(), sock, changes)
		close(done)
	}()

	for _, msgType := range []uint8{unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_GET, unix.RTM_MISS} {
		_, err := unix.Write(kernel, routeMsg(msgType, 8))
		require.NoError(t, err)
	}

	select {
	case <-changes:
		t.Fatal("route churn alone must not report a change")
	case <-time.After(netChangeSettleWindow * 2):
	}

	require.NoError(t, sock.Close())
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("watchRouteSocket did not return after the socket was closed")
	}
}

// TestWatchRouteSocketDropsRatherThanBlocks covers the coalescing send. A reader that is busy rebinding must not
// wedge the watcher, and a second pending "the network moved" tells it nothing new anyway.
func TestWatchRouteSocketDropsRatherThanBlocks(t *testing.T) {
	sock, kernel := socketPair(t)
	changes := make(chan struct{}, 1)

	done := make(chan struct{})
	go func() {
		watchRouteSocket(test.NewLogger(), sock, changes)
		close(done)
	}()

	// Nobody is reading changes, so after the first report the buffer is full for the rest of this test
	for range 3 {
		_, err := unix.Write(kernel, routeMsg(unix.RTM_NEWADDR, 8))
		require.NoError(t, err)
		time.Sleep(netChangeSettleWindow + time.Millisecond*250)
	}

	// The watcher must still be alive and responsive to a close
	require.NoError(t, sock.Close())
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("watchRouteSocket wedged on a full channel")
	}

	assert.Len(t, changes, 1, "the pending report should have coalesced, not queued")
}

// TestWatchNetworkChangesStopsWithContext covers the detection path against a real routing socket, including that
// cancelling the context closes the channel so a ranging caller falls out of its loop.
func TestWatchNetworkChangesStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	changes, err := watchNetworkChanges(ctx, test.NewLogger())
	require.NoError(t, err)
	require.NotNil(t, changes, "darwin should support watching")

	drained := make(chan struct{})
	go func() {
		for range changes {
		}
		close(drained)
	}()

	cancel()
	select {
	case <-drained:
	case <-time.After(time.Second * 5):
		t.Fatal("cancelling the context should close the changes channel")
	}
}

// TestNetworkChangeMonitorStopsWithContext drives the whole monitor against a real routing socket: Start must block
// watching, and cancelling the context (which is all Control does on shutdown, it never stops the monitor directly)
// must return it and clean up the watch goroutines.
func TestNetworkChangeMonitorStopsWithContext(t *testing.T) {
	// IgnoreCurrent because other tests in this package leave readers running; we only care about what this test
	// leaks itself.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(context.Background())

	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("listen:\n  rebind_on_network_change: true\n"))
	m := NewNetworkChangeMonitor(ctx, l, c, func() {})

	done := make(chan struct{})
	go func() {
		m.Start()
		close(done)
	}()

	// Start should be sitting on the routing socket, not have fallen out. If it returned early it either failed to
	// watch or no-op'd, both of which we want to catch.
	select {
	case <-done:
		t.Fatal("Start returned instead of watching")
	case <-time.After(time.Millisecond * 250):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("Start did not return after the context was cancelled")
	}

	// Starting again after the context is dead must not open anything.
	m.Start()
}
