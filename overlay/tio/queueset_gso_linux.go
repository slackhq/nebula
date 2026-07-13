//go:build linux && !android
// +build linux,!android

package tio

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type offloadQueueSet struct {
	pq []*Offload
	// pqi is exactly the same as pq, but stored as the interface type
	pqi        []Queue
	shutdownFd int
	// usoEnabled is true when newTun successfully negotiated TUN_F_USO4|6
	// with the kernel. Queues created by Add inherit this and surface it
	// via Offload.USOSupported so coalescers can gate USO emission.
	usoEnabled bool
}

// NewOffloadQueueSet creates a QueueSet that uses virtio_net_hdr to do
// TSO segmentation in userspace. usoEnabled tells downstream queues whether
// the kernel agreed to deliver/accept GSO_UDP_L4 superpackets — coalescers
// should fall back to per-packet writes when this is false.
func NewOffloadQueueSet(usoEnabled bool) (QueueSet, error) {
	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &offloadQueueSet{
		pq:         []*Offload{},
		pqi:        []Queue{},
		shutdownFd: shutdownFd,
		usoEnabled: usoEnabled,
	}

	return out, nil
}

func (c *offloadQueueSet) Queues() []Queue {
	return c.pqi
}

func (c *offloadQueueSet) Add(fd int) error {
	x, err := newOffload(fd, c.shutdownFd, c.usoEnabled)
	if err != nil {
		return err
	}
	c.pq = append(c.pq, x)
	c.pqi = append(c.pqi, x)

	return nil
}

func (c *offloadQueueSet) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(c.shutdownFd, buf[:])
	return err
}

func (c *offloadQueueSet) Close() error {
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
