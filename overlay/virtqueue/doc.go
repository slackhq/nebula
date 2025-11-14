// Package virtqueue implements the driver-side for a virtio queue as described
// in the specification:
// https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-270006
// This package does not make assumptions about the device that consumes the
// queue. It rather just allocates the queue structures in memory and provides
// methods to interact with it.
package virtqueue
