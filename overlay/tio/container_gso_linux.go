package tio

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type offloadContainer struct {
	pq []*Offload
	// pqi is exactly the same as pq, but stored as the interface type
	pqi        []Queue
	shutdownFd int
}

func NewOffloadContainer() (Container, error) {
	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &offloadContainer{
		pq:         []*Offload{},
		pqi:        []Queue{},
		shutdownFd: shutdownFd,
	}

	return out, nil
}

func (c *offloadContainer) Queues() []Queue {
	return c.pqi
}

func (c *offloadContainer) Add(fd int) error {
	x, err := newOffload(fd, c.shutdownFd)
	if err != nil {
		return err
	}
	c.pq = append(c.pq, x)
	c.pqi = append(c.pqi, x)

	return nil
}

func (c *offloadContainer) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(c.shutdownFd, buf[:])
	return err
}

func (c *offloadContainer) Close() error {
	errs := []error{}

	// Signal all readers blocked in poll to wake up and exit
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
