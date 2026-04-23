//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package tio

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newReadPipe returns a read fd. The matching write fd is registered for cleanup.
// The caller takes ownership of the read fd (pass it to newOffload / newFriend).
func newReadPipe(t *testing.T) int {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	return fds[0]
}

func TestOffload_WakeForShutdown_WakesFriends(t *testing.T) {
	pipe1 := newReadPipe(t)
	pipe2 := newReadPipe(t)
	parent, err := NewOffloadContainer()
	if err != nil {
		t.Fatalf("newOffload: %v", err)
	}
	require.NoError(t, parent.Add(pipe1))
	require.NoError(t, parent.Add(pipe2))
	t.Cleanup(func() {
		_ = unix.Close(pipe1)
		_ = unix.Close(pipe2)
	})

	readers := parent.Queues()
	errs := make([]error, len(readers))
	var wg sync.WaitGroup
	for i, r := range readers {
		wg.Add(1)
		go func(i int, r Queue) {
			defer wg.Done()
			_, errs[i] = r.Read()
		}(i, r)
	}

	time.Sleep(50 * time.Millisecond)

	if err := parent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readers did not wake")
	}

	for i, err := range errs {
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("reader %d: expected os.ErrClosed, got %v", i, err)
		}
	}
}

func TestTunFile_Close_Idempotent(t *testing.T) {
	tf, err := newOffload(newReadPipe(t), 1)
	if err != nil {
		t.Fatalf("newOffload: %v", err)
	}
	if err := tf.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tf.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}
