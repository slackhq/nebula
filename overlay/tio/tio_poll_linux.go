//go:build linux && !android
// +build linux,!android

package tio

import (
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Maximum size we accept for a single read from a TUN with IFF_VNET_HDR. A
// TSO superpacket can be up to 64KiB of payload plus a single L2/L3/L4 header
// prefix plus the virtio header.
const tunReadBufSize = 65535

type Poll struct {
	fd int

	readPoll  [2]unix.PollFd
	writePoll [2]unix.PollFd
	closed    atomic.Bool

	readBuf  []byte
	batchRet [1]Packet
}

// newPoll wraps an existing tun fd. On failure it does NOT close fd: the
// caller owns fd and is the sole closer (see pollQueueSet.Add callers in
// overlay/tun_linux.go, which unix.Close on Add error). This matches the
// newOffload convention and keeps closes at exactly one on every path.
func newPoll(fd int, shutdownFd int) (*Poll, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set Poll device as nonblocking: %w", err)
	}

	out := &Poll{
		fd:      fd,
		readBuf: make([]byte, tunReadBufSize),
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
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
	tunEvents := t.writePoll[0].Revents
	shutdownEvents := t.writePoll[1].Revents
	t.writePoll[0].Revents = 0
	t.writePoll[1].Revents = 0
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

// Write is only valid for single threaded use
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
