//go:build linux && !android
// +build linux,!android

package tio

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type pollQueueSet struct {
	pq []*Poll
	// pqi is exactly the same as pq, but stored as the interface type
	pqi        []Queue
	shutdownFd int
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
	errs := []error{}

	if err := c.wakeForShutdown(); err != nil {
		errs = append(errs, err)
	}

	for _, x := range c.pq {
		if err := x.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
