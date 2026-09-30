//go:build darwin || send_pipeline

package nebula

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

// scriptedQueue hands out reads from a script, then fails every Read with err.
type scriptedQueue struct {
	reads [][]tio.Packet
	err   error
}

func (q *scriptedQueue) Read() ([]tio.Packet, error) {
	if len(q.reads) == 0 {
		return nil, q.err
	}
	r := q.reads[0]
	q.reads = q.reads[1:]
	return r, nil
}
func (q *scriptedQueue) Write(b []byte) (int, error) { return len(b), nil }
func (q *scriptedQueue) Close() error                { return nil }

type countingConn struct {
	udp.NoopConn
	mu      sync.Mutex
	batches int
}

func (c *countingConn) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	c.mu.Lock()
	c.batches++
	c.mu.Unlock()
	return len(bufs), nil
}

// TestListenInPipelinedStops pins that the pipelined reader returns when its queue fails, stopping its sender, and
// reports the error as fatal only when the interface isn't shutting down.
func TestListenInPipelinedStops(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "fatal", true: "shutdown"}[closing], func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			readErr := errors.New("tun gone")
			conn := &countingConn{}
			// Packets too short to parse are dropped before the firewall, so this reads without a hostmap.
			junk := tio.Packet{Bytes: []byte{0x45, 0}}
			q := &scriptedQueue{reads: [][]tio.Packet{{junk}, {junk, junk, junk}, {}}, err: readErr}
			shutdown := make(chan struct{})
			f := &Interface{
				ctx:             context.Background(),
				l:               test.NewLogger(),
				writers:         []udp.Conn{conn},
				triggerShutdown: func() { close(shutdown) },
			}
			f.closed.Store(closing)

			done := make(chan struct{})
			go func() {
				f.listenIn(q, 0)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("listenIn did not return after its queue failed")
			}
			if closing {
				assert.Nil(t, f.fatalErr.Load())
			} else {
				<-shutdown
				assert.Equal(t, readErr, *f.fatalErr.Load())
			}
			assert.Zero(t, conn.batches, "dropped packets must not be written")
		})
	}
}
