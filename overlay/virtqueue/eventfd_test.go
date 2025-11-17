package virtqueue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/eventfd"
)

// Tests how an eventfd and a waiting goroutine can be gracefully closed.
// Extends the eventfd test suite:
// https://github.com/google/gvisor/blob/0799336d64be65eb97d330606c30162dc3440cab/pkg/eventfd/eventfd_test.go
func TestEventFD_CancelWait(t *testing.T) {
	efd, err := eventfd.Create()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, efd.Close())
	})

	var stop bool

	done := make(chan struct{})
	go func() {
		for !stop {
			_ = efd.Wait()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatalf("goroutine ended early")
	case <-time.After(500 * time.Millisecond):
	}

	stop = true
	assert.NoError(t, efd.Notify())
	select {
	case <-done:
		break
	case <-time.After(5 * time.Second):
		t.Error("goroutine did not end")
	}
}
