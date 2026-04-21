package tio

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type gsoContainer struct {
	pq []*tunFile
	// pqi is exactly the same as pq, but stored as the interface type
	pqi        []Queue
	shutdownFd int
}

func NewGSOContainer() (Container, error) {
	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &gsoContainer{
		pq:         []*tunFile{},
		pqi:        []Queue{},
		shutdownFd: shutdownFd,
	}

	return out, nil
}

func (c *gsoContainer) Queues() []Queue {
	return c.pqi
}

func (c *gsoContainer) Add(fd int) error {
	x, err := newTunFd(fd, c.shutdownFd)
	if err != nil {
		return err
	}
	c.pq = append(c.pq, x)
	c.pqi = append(c.pqi, x)

	return nil
}

func (c *gsoContainer) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(int(c.shutdownFd), buf[:])
	return err
}

func (c *gsoContainer) Close() error {
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
