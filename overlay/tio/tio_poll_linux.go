package tio

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/wire"
	"golang.org/x/sys/unix"
)

type Poll struct {
	fd int

	readPoll  [2]unix.PollFd
	writePoll [2]unix.PollFd
	writeLock sync.Mutex
	closed    atomic.Bool
}

func newPoll(fd int, shutdownFd int) (*Poll, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to set Poll device as nonblocking: %w", err)
	}

	out := &Poll{
		fd: fd,
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writeLock: sync.Mutex{},
	}
	return out, nil
}

// blockOnRead waits until the Poll fd is readable or shutdown has been signaled.
// Returns os.ErrClosed if Close was called.
func (t *Poll) blockOnRead() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(t.readPoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	tunEvents := t.readPoll[0].Revents
	shutdownEvents := t.readPoll[1].Revents
	t.readPoll[0].Revents = 0
	t.readPoll[1].Revents = 0
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

func (t *Poll) blockOnWrite() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(t.writePoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	t.writeLock.Lock()
	tunEvents := t.writePoll[0].Revents
	shutdownEvents := t.writePoll[1].Revents
	t.writePoll[0].Revents = 0
	t.writePoll[1].Revents = 0
	t.writeLock.Unlock()
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

func (t *Poll) Read(p []wire.TunPacket, mem []byte) (int, error) {
	if len(p) == 0 || len(mem) == 0 {
		return 0, nil //todo should this be an err?
	}
	p[0].Meta = struct{}{}
	n, err := t.readOne(mem)
	if err != nil {
		return 0, err
	}
	p[0].Bytes = mem[:n]
	return 1, nil
}

func (t *Poll) readOne(to []byte) (int, error) {
	for {
		n, errno := unix.Read(t.fd, to)
		if errno == nil {
			return n, nil
		}
		switch errno {
		case unix.EAGAIN:
			if err := t.blockOnRead(); err != nil {
				return 0, err
			}
		case unix.EINTR:
			// retry
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, errno
		}
	}
}

func (t *Poll) Write(from []byte) (int, error) {
	for {
		n, errno := unix.Write(t.fd, from)
		if errno == nil {
			return n, nil
		}
		switch errno {
		case unix.EAGAIN:
			if err := t.blockOnWrite(); err != nil {
				return 0, err
			}
		case unix.EINTR:
			// retry
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, errno
		}
	}
}

func (t *Poll) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	//shutdownFd is owned by the container, so we should not close it
	var err error
	if t.fd >= 0 {
		err = unix.Close(t.fd)
		t.fd = -1
	}

	return err
}

func (t *Poll) Capabilities() Capabilities {
	return Capabilities{}
}
