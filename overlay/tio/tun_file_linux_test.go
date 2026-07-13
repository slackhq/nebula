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
// The caller takes ownership of the read fd (pass it into a QueueSet).
func newReadPipe(t *testing.T) int {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	return fds[0]
}

func TestPoll_WakeForShutdown_WakesFriends(t *testing.T) {
	pipe1 := newReadPipe(t)
	pipe2 := newReadPipe(t)
	parent, err := NewPollQueueSet()
	require.NoError(t, err)
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

// TestPoll_ConcurrentWrite_NoRace hammers a single Poll queue from two writer
// goroutines while a reader drains the other end of the pipe. The writers
// overflow the pipe buffer, so both repeatedly park in blockOnWrite at the same
// time — the exact scenario that raced on the old shared writePoll member
// array. Run under -race; a shared-array regression trips the detector here.
func TestPoll_ConcurrentWrite_NoRace(t *testing.T) {
	var fds [2]int
	require.NoError(t, unix.Pipe2(fds[:], unix.O_CLOEXEC))
	readFd, writeFd := fds[0], fds[1]

	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(shutdownFd) })

	p, err := newPoll(writeFd, shutdownFd)
	require.NoError(t, err)

	const writers = 2
	const perWriter = 4000
	payload := make([]byte, 100)
	total := writers * perWriter * len(payload)

	// Reader: drain the read end (blocking) until every writer's bytes are
	// consumed, so the writers keep making progress rather than wedging on a
	// permanently full pipe.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		got := 0
		for got < total {
			n, rerr := unix.Read(readFd, buf)
			got += n
			if rerr != nil {
				if rerr == unix.EINTR {
					continue
				}
				return
			}
			if n == 0 { // EOF
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, werr := p.Write(payload); werr != nil {
					t.Errorf("write: %v", werr)
					return
				}
			}
		}()
	}
	wg.Wait()

	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("reader did not drain")
	}

	require.NoError(t, p.Close())
	_ = unix.Close(readFd)
}

// TestPoll_NewPoll_DoesNotCloseFdOnFailure pins the ownership rule: when
// newPoll fails, it must leave fd open so the caller (pollQueueSet.Add's
// callers in tun_linux.go) is the sole closer. If newPoll also closed fd,
// the poll path would double-close on Add error. We force the failure with
// an O_PATH descriptor: fcntl(F_SETFL) — which SetNonblock performs — is not
// permitted on O_PATH fds and fails with EBADF, while the fd itself stays
// open so we can observe that newPoll left it alone.
func TestPoll_NewPoll_DoesNotCloseFdOnFailure(t *testing.T) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })

	p, err := newPoll(fd, 1)
	require.Error(t, err, "SetNonblock on an O_PATH fd should fail")
	require.Nil(t, p)

	// If newPoll had closed fd, F_GETFD would report it closed. It staying
	// open proves newPoll left the fd for the caller to close exactly once.
	require.True(t, fdOpen(t, fd), "newPoll must not close fd on failure; caller is the sole closer")
}

func TestPoll_Close_Idempotent(t *testing.T) {
	tf, err := newPoll(newReadPipe(t), 1)
	require.NoError(t, err)
	if err := tf.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tf.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}

// fdOpen reports whether fd currently refers to an open file description.
// A closed (or never-allocated) fd makes F_GETFD fail with EBADF.
func fdOpen(t *testing.T, fd int) bool {
	t.Helper()
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err == nil {
		return true
	}
	if errors.Is(err, unix.EBADF) {
		return false
	}
	t.Fatalf("unexpected fcntl(F_GETFD) error on fd %d: %v", fd, err)
	return false
}

// TestPollQueueSet_Close_ClosesShutdownFd is the regression test for the
// leaked shutdown eventfd: the container that owns shutdownFd must close it in
// Close, and a second Close must be a safe no-op.
func TestPollQueueSet_Close_ClosesShutdownFd(t *testing.T) {
	qs, err := NewPollQueueSet()
	require.NoError(t, err)
	c, ok := qs.(*pollQueueSet)
	require.True(t, ok)
	require.NoError(t, qs.Add(newReadPipe(t)))

	shutdownFd := c.shutdownFd
	require.True(t, fdOpen(t, shutdownFd), "shutdown eventfd should be open before Close")

	require.NoError(t, qs.Close())
	require.False(t, fdOpen(t, shutdownFd), "shutdown eventfd should be closed after Close")

	// Second Close must not touch fds (shutdownFd is now -1) and must return nil.
	require.NoError(t, qs.Close())
}

// TestOffloadQueueSet_Close_ClosesShutdownFd mirrors the poll regression test
// for the GSO/offload queueset.
func TestOffloadQueueSet_Close_ClosesShutdownFd(t *testing.T) {
	qs, err := NewOffloadQueueSet(false)
	require.NoError(t, err)
	c, ok := qs.(*offloadQueueSet)
	require.True(t, ok)
	require.NoError(t, qs.Add(newReadPipe(t)))

	shutdownFd := c.shutdownFd
	require.True(t, fdOpen(t, shutdownFd), "shutdown eventfd should be open before Close")

	require.NoError(t, qs.Close())
	require.False(t, fdOpen(t, shutdownFd), "shutdown eventfd should be closed after Close")

	// Second Close must not touch fds (shutdownFd is now -1) and must return nil.
	require.NoError(t, qs.Close())
}
