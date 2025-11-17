package vhostnet

import (
	"errors"

	"github.com/slackhq/nebula/overlay/virtqueue"
)

type optionValues struct {
	queueSize int
	backendFD int
}

func (o *optionValues) apply(options []Option) {
	for _, option := range options {
		option(o)
	}
}

func (o *optionValues) validate() error {
	if o.queueSize == -1 {
		return errors.New("queue size is required")
	}
	if err := virtqueue.CheckQueueSize(o.queueSize); err != nil {
		return err
	}
	if o.backendFD == -1 {
		return errors.New("backend file descriptor is required")
	}
	return nil
}

var optionDefaults = optionValues{
	// Required.
	queueSize: -1,
	// Required.
	backendFD: -1,
}

// Option can be passed to [NewDevice] to influence device creation.
type Option func(*optionValues)

// WithQueueSize returns an [Option] that sets the size of the TX and RX queues
// that are to be created for the device. It specifies the number of
// entries/buffers each queue can hold. This also affects the memory
// consumption.
// This is required and must be an integer from 1 to 32768 that is also a power
// of 2.
func WithQueueSize(queueSize int) Option {
	return func(o *optionValues) { o.queueSize = queueSize }
}

// WithBackendFD returns an [Option] that sets the file descriptor of the
// backend that will be used for the queues of the device. The device will write
// and read packets to/from that backend. The file descriptor can either be of a
// RAW socket or TUN/TAP device.
// Either this or [WithBackendDevice] is required.
func WithBackendFD(backendFD int) Option {
	return func(o *optionValues) { o.backendFD = backendFD }
}

//// WithBackendDevice returns an [Option] that sets the given TAP device as the
//// backend that will be used for the queues of the device. The device will
//// write and read packets to/from that backend. The TAP device should have been
//// created with the [tuntap.WithVirtioNetHdr] option enabled.
//// Either this or [WithBackendFD] is required.
//func WithBackendDevice(dev *tuntap.Device) Option {
//	return func(o *optionValues) { o.backendFD = int(dev.File().Fd()) }
//}
