//go:build linux && !android
// +build linux,!android

package tio

import (
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Maximum size we accept for a single read from a TUN. 65535 covers any
// single IP packet.
const tunReadBufSize = 65535

type Poll struct {
	fd         int
	shutdownFd int
	closed     atomic.Bool

	readBuf  []byte
	batchRet [1]Packet
}

// newPoll wraps an existing tun fd. On failure it does NOT close fd: the
// caller owns fd and is the sole closer (see pollQueueSet.Add callers in
// overlay/tun_linux.go, which unix.Close on Add error). This keeps closes
// at exactly one on every path.
func newPoll(fd int, shutdownFd int) (*Poll, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set Poll device as nonblocking: %w", err)
	}

	out := &Poll{
		fd:         fd,
		shutdownFd: shutdownFd,
		readBuf:    make([]byte, tunReadBufSize),
	}
	return out, nil
}

// blockOnRead waits until the Poll fd is readable or shutdown has been signaled.
// Returns os.ErrClosed if Close was called.
func (t *Poll) blockOnRead() error {
	return blockOn(int32(t.fd), int32(t.shutdownFd), unix.POLLIN)
}

func (t *Poll) blockOnWrite() error {
	return blockOn(int32(t.fd), int32(t.shutdownFd), unix.POLLOUT)
}

func (t *Poll) Read() ([]Packet, error) {
	n, err := t.readOne(t.readBuf)
	if err != nil {
		return nil, err
	}
	t.batchRet[0] = Packet{Bytes: t.readBuf[:n]}
	return t.batchRet[:], nil
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

// Write is safe for concurrent use
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
	// Close the underlying fd but do NOT null t.fd: a reader may still be
	// loading it in readOne, and mutating the field would race that load.
	// It gets EBADF -> os.ErrClosed (or wakes via the shutdown eventfd's
	// ppoll first). closed.Swap already guarantees we only close once.
	return unix.Close(t.fd)
}
