//go:build linux && !android

package tio

import (
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type Poll struct {
	fd         int
	shutdownFd int
	closed     atomic.Bool

	readBuf  []byte
	batchRet [1]Packet
}

// newPoll wraps an existing tun fd.
// On failure it does NOT close fd: the caller owns fd and is the sole closer
// (see pollQueueSet.Add callers in overlay/tun_linux.go, which unix.Close on Add error).
// This matches the newOffload convention and keeps closes at exactly one on every path.
func newPoll(fd int, shutdownFd int) (*Poll, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set Poll device as nonblocking: %w", err)
	}

	out := &Poll{
		fd:         fd,
		shutdownFd: shutdownFd,
		readBuf:    make([]byte, 65535), // largest possible size Linux permits
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

// TODO: port Offload's post-wake drain loop here so one poll wake amortizes
// over a burst (up to tunDrainCap packets) instead of paying a syscall and a
// wake per packet. Hosts on the TUNSETOFFLOAD-failure fallback or a tun.fd
// config currently lose that batching. blockOn and the EAGAIN plumbing are
// already shared; kept one-packet-per-Read for now to preserve behavior.
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

	// shutdownFd is owned by the container, so we should not close it
	// Close the underlying fd but do NOT null t.fd: a reader may still be loading it in readOne, and mutating the field would race that load.
	// That reader gets EBADF -> os.ErrClosed on its next syscall. A reader already parked in
	// poll is NOT woken by this close; only the QueueSet's shutdown eventfd wake does that (see Queue.Close docs).
	// closed.Swap already guarantees we only close once.
	return unix.Close(t.fd)
}
