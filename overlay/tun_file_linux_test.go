//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package overlay

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newReadPipe returns a read fd. The matching write fd is registered for cleanup.
// The caller takes ownership of the read fd (pass it to newTunFd / newFriend).
func newReadPipe(t *testing.T) int {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	return fds[0]
}

func TestTunFile_WakeForShutdown_UnblocksRead(t *testing.T) {
	tf, err := newTunFd(newReadPipe(t))
	if err != nil {
		t.Fatalf("newTunFd: %v", err)
	}
	t.Cleanup(func() { _ = tf.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := tf.Read(make([]byte, 64))
		done <- err
	}()

	// Verify Read is actually blocked in poll.
	select {
	case err := <-done:
		t.Fatalf("Read returned before shutdown signal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := tf.wakeForShutdown(); err != nil {
		t.Fatalf("wakeForShutdown: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("expected os.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not wake on shutdown")
	}
}

func TestTunFile_WakeForShutdown_WakesFriends(t *testing.T) {
	parent, err := newTunFd(newReadPipe(t))
	if err != nil {
		t.Fatalf("newTunFd: %v", err)
	}
	friend, err := parent.newFriend(newReadPipe(t))
	if err != nil {
		_ = parent.Close()
		t.Fatalf("newFriend: %v", err)
	}
	t.Cleanup(func() {
		_ = friend.Close()
		_ = parent.Close()
	})

	readers := []*tunFile{parent, friend}
	errs := make([]error, len(readers))
	var wg sync.WaitGroup
	for i, r := range readers {
		wg.Add(1)
		go func(i int, r *tunFile) {
			defer wg.Done()
			_, errs[i] = r.Read(make([]byte, 64))
		}(i, r)
	}

	time.Sleep(50 * time.Millisecond)

	if err := parent.wakeForShutdown(); err != nil {
		t.Fatalf("wakeForShutdown: %v", err)
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
	tf, err := newTunFd(newReadPipe(t))
	if err != nil {
		t.Fatalf("newTunFd: %v", err)
	}
	if err := tf.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tf.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}
