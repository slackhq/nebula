package nebula

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDevice struct {
	closeOnce sync.Once
	closedCh  chan struct{}
	closed    bool
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{closedCh: make(chan struct{})}
}

// Read blocks until Close like a real tun with no traffic, then reports EOF
// the same way a closed device does
func (d *fakeDevice) Read() ([]tio.Packet, error) {
	<-d.closedCh
	return nil, io.EOF
}

func (d *fakeDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *fakeDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closed = true
		close(d.closedCh)
	})
	return nil
}

func (d *fakeDevice) Activate() error                       { return nil }
func (d *fakeDevice) Networks() []netip.Prefix              { return nil }
func (d *fakeDevice) Name() string                          { return "fake" }
func (d *fakeDevice) RoutesFor(netip.Addr) routing.Gateways { return nil }

func (d *fakeDevice) Queues(int) ([]tio.Queue, error) { return []tio.Queue{d}, nil }

// newReadyControl hand-builds the minimum Control that Main would have
// produced right before Start, including the construction token NewInterface
// takes so waiters block until Close releases the resources
func newReadyControl(t *testing.T) (*Control, *fakeDevice, *fakeConn) {
	l := test.NewLogger()
	dev := newFakeDevice()
	conn := &fakeConn{}
	ctx, cancel := context.WithCancel(context.Background())

	myVpnNet := netip.MustParsePrefix("10.128.0.1/16")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}
	lh, err := NewLightHouseFromConfig(ctx, l, config.NewC(l), cs, nil, nil)
	require.NoError(t, err)

	f := &Interface{
		ctx:        ctx,
		inside:     dev,
		outside:    conn,
		writers:    []udp.Conn{conn},
		routines:   1,
		hostMap:    newHostMap(l),
		lightHouse: lh,
		l:          l,
	}
	f.wg.Add(1)

	return &Control{
		state:  StateReady,
		f:      f,
		l:      l,
		ctx:    ctx,
		cancel: cancel,
	}, dev, conn
}

func TestControl_StopBeforeStart(t *testing.T) {
	c, dev, conn := newReadyControl(t)

	// A Stop on a never started control must release everything Main acquired
	c.Stop()
	assert.Equal(t, StateStopped, c.State())
	assert.True(t, dev.closed, "the tun device should have been closed")
	assert.True(t, conn.closed, "the udp socket should have been closed")
	require.ErrorIs(t, c.ctx.Err(), context.Canceled, "the service context should have been cancelled")

	// Wait must return promptly now that the resources are released
	require.NoError(t, c.Wait())

	// A stopped control can never be started
	require.ErrorIs(t, c.Start(), ErrAlreadyStopped)

	// A second Stop is a harmless no-op
	c.Stop()
	assert.Equal(t, StateStopped, c.State())
	require.NoError(t, c.Wait())
}

func TestControl_WaitBlocksUntilStop(t *testing.T) {
	c, _, _ := newReadyControl(t)

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	select {
	case <-done:
		t.Fatal("Wait returned before Stop")
	case <-time.After(50 * time.Millisecond):
	}

	c.Stop()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Stop")
	}
}

type fakeConn struct {
	closed  bool
	rebinds int
}

func (c *fakeConn) Rebind() error                            { c.rebinds++; return nil }
func (c *fakeConn) LocalAddr() (netip.AddrPort, error)       { return netip.AddrPort{}, nil }
func (c *fakeConn) ListenOut(_ udp.EncReader) error          { return nil }
func (c *fakeConn) WriteTo(_ []byte, _ netip.AddrPort) error { return nil }
func (c *fakeConn) ReloadConfig(_ *config.C)                 {}
func (c *fakeConn) SupportsMultipleReaders() bool            { return true }
func (c *fakeConn) Close() error                             { c.closed = true; return nil }

type multiqueueDevice struct {
	*fakeDevice
}

// Queues claims multiqueue support but fails to open the second queue,
// exercising the activation error path.
func (d *multiqueueDevice) Queues(n int) ([]tio.Queue, error) {
	if n > 1 {
		return nil, errors.New("second queue failed to open")
	}
	return d.fakeDevice.Queues(n)
}

func TestControl_StartMultiqueueFailureReleases(t *testing.T) {
	dev := &multiqueueDevice{fakeDevice: newFakeDevice()}
	conn := &fakeConn{}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Interface{
		ctx:      ctx,
		inside:   dev,
		outside:  conn,
		writers:  []udp.Conn{conn},
		routines: 2,
		l:        test.NewLogger(),
	}
	f.wg.Add(1)

	c := &Control{
		state:  StateReady,
		f:      f,
		l:      test.NewLogger(),
		ctx:    ctx,
		cancel: cancel,
	}

	// The second reader fails to open, everything must be released
	require.Error(t, c.Start())
	assert.Equal(t, StateStopped, c.State())
	assert.True(t, dev.closed, "the tun device should have been closed")
	assert.True(t, conn.closed, "the udp socket should have been closed")
	require.ErrorIs(t, c.ctx.Err(), context.Canceled)

	// And Wait must not hang on the construction token
	require.NoError(t, c.Wait())
}

func TestInterface_CloseIsIdempotent(t *testing.T) {
	dev := newFakeDevice()
	f := &Interface{
		inside: dev,
		l:      test.NewLogger(),
	}
	f.wg.Add(1)

	require.NoError(t, f.Close())
	assert.True(t, dev.closed)

	// A second Close must not double release the wg token or the device
	require.NoError(t, f.Close())
	require.NoError(t, f.wait())
}

func TestControl_FatalErrorReportsThroughWait(t *testing.T) {
	c, dev, conn := newReadyControl(t)

	// Mirror what Start wires up, without needing real packet readers
	c.f.triggerShutdown = c.Stop
	c.state = StateStarted

	boom := errors.New("boom")
	c.f.onFatal(boom)

	require.ErrorIs(t, c.Wait(), boom)
	assert.Equal(t, StateStopped, c.State())
	assert.True(t, dev.closed)
	assert.True(t, conn.closed)

	// A second fatal error must not fire the shutdown again or replace the first
	c.f.onFatal(errors.New("later"))
	require.ErrorIs(t, c.Wait(), boom)

	// Wait stays factual, a Stop after the death does not mask the error
	c.Stop()
	require.ErrorIs(t, c.Wait(), boom)
}

func TestControl_ConcurrentStopAndStart(t *testing.T) {
	c, _, _ := newReadyControl(t)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Go(func() { c.Stop() })
	}
	wg.Go(func() { _ = c.Start() })
	wg.Go(func() {
		_ = c.Wait()
		// A returned Wait must always observe the final state, no matter how
		// the race resolved
		assert.Equal(t, StateStopped, c.State())
	})
	wg.Wait()

	// However the race resolves, the control must end fully stopped with no
	// panic and Wait must observe the final state
	require.NoError(t, c.Wait())
	assert.Equal(t, StateStopped, c.State())
	require.ErrorIs(t, c.Start(), ErrAlreadyStopped)
}

func TestControl_StartStopLifecycle(t *testing.T) {
	c, dev, conn := newReadyControl(t)

	require.NoError(t, c.Start())
	assert.Equal(t, StateStarted, c.State())
	require.ErrorIs(t, c.Start(), ErrAlreadyStarted)

	// Stop must unpark the reader blocked in the device and release everything
	c.Stop()
	assert.Equal(t, StateStopped, c.State())
	assert.True(t, dev.closed, "the tun device should have been closed")
	assert.True(t, conn.closed, "the udp socket should have been closed")
	require.ErrorIs(t, c.ctx.Err(), context.Canceled)

	// The reader drained off a closed device, that is not a fatal error
	require.NoError(t, c.Wait())
	require.ErrorIs(t, c.Start(), ErrAlreadyStopped)
}

func TestControl_RebindIsGatedByState(t *testing.T) {
	c, _, conn := newReadyControl(t)

	// A rebind before Start reaches nothing, the interface is not up
	c.RebindUDPServer()
	assert.Equal(t, 0, conn.rebinds, "rebind before start must be a no-op")

	require.NoError(t, c.Start())
	c.RebindUDPServer()
	assert.Equal(t, 1, conn.rebinds, "rebind while started must reach the conn")

	// A rebind racing a completed stop must not touch the closed conn
	c.Stop()
	require.NoError(t, c.Wait())
	c.RebindUDPServer()
	assert.Equal(t, 1, conn.rebinds, "rebind after stop must be a no-op")
}
