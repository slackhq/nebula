//go:build linux && !android

package tio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type pollQueueSet struct {
	pq []*Poll
	// pqi is exactly the same as pq, but stored as the interface type
	pqi        []Queue
	shutdownFd int
	closed     atomic.Bool
}

func NewPollQueueSet() (QueueSet, error) {
	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &pollQueueSet{
		pq:         []*Poll{},
		pqi:        []Queue{},
		shutdownFd: shutdownFd,
	}

	return out, nil
}

func (c *pollQueueSet) Queues() []Queue {
	return c.pqi
}

func (c *pollQueueSet) Add(fd int) error {
	if c.closed.Load() {
		return errors.New("queue set already closed")
	}
	x, err := newPoll(fd, c.shutdownFd)
	if err != nil {
		return err
	}
	c.pq = append(c.pq, x)
	c.pqi = append(c.pqi, x)

	return nil
}

func (c *pollQueueSet) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(int(c.shutdownFd), buf[:])
	return err
}

func (c *pollQueueSet) Close() error {
	if c.closed.Swap(true) {
		return nil
	}

	errs := []error{}

	// Signal all readers blocked in poll to wake up and exit.
	// They observe POLLIN on the shutdown eventfd and return os.ErrClosed.
	if err := c.wakeForShutdown(); err != nil {
		errs = append(errs, err)
	}

	// Close the per-queue tun fds; this also unblocks any in-flight reads.
	for _, x := range c.pq {
		if err := x.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close the shutdown eventfd last: every reader's pollfd set references it,
	// so it must outlive the wake + per-queue teardown above.
	if err := unix.Close(c.shutdownFd); err != nil {
		errs = append(errs, err)
	}
	c.shutdownFd = -1

	return errors.Join(errs...)
}
