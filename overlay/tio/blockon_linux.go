//go:build linux && !android
// +build linux,!android

package tio

import (
	"os"

	"golang.org/x/sys/unix"
)

// blockOn parks the calling goroutine until fd is ready (events is POLLIN for
// reads, POLLOUT for writes) or shutdownFd signals teardown. It builds the
// pollfd array on the stack every call, so concurrent callers on the same
// Queue never share Revents storage.
//
// Returns os.ErrClosed when shutdown was signaled (POLLIN on shutdownFd)
// or either fd reported a problem condition (POLLHUP|POLLNVAL|POLLERR).
func blockOn(fd, shutdownFd int32, events int16) error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	pfds := [2]unix.PollFd{
		{Fd: fd, Events: events},
		{Fd: shutdownFd, Events: unix.POLLIN},
	}
	var err error
	for {
		_, err = unix.Poll(pfds[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	tunEvents := pfds[0].Revents
	shutdownEvents := pfds[1].Revents
	// Check err before trusting the potentially bogus bits we just got.
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	}
	if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}
