package vhostnet

import (
	"fmt"
	"unsafe"

	"github.com/slackhq/nebula/overlay/vhost"
)

const (
	// vhostNetIoctlSetBackend can be used to attach a virtqueue to a RAW socket
	// or TAP device.
	//
	// Request payload: [vhost.QueueFile]
	// Kernel name: VHOST_NET_SET_BACKEND
	vhostNetIoctlSetBackend = 0x4008af30
)

// SetQueueBackend attaches a virtqueue of the vhost networking device
// described by controlFD to the given backend file descriptor.
// The backend file descriptor can either be a RAW socket or a TAP device. When
// it is -1, the queue will be detached.
func SetQueueBackend(controlFD int, queueIndex uint32, backendFD int) error {
	if err := vhost.IoctlPtr(controlFD, vhostNetIoctlSetBackend, unsafe.Pointer(&vhost.QueueFile{
		QueueIndex: queueIndex,
		FD:         int32(backendFD),
	})); err != nil {
		return fmt.Errorf("set queue backend file descriptor: %w", err)
	}
	return nil
}
