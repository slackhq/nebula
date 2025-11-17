package vhost

import (
	"fmt"
	"unsafe"

	"github.com/slackhq/nebula/overlay/virtqueue"
	"github.com/slackhq/nebula/util/virtio"
	"golang.org/x/sys/unix"
)

const (
	// vhostIoctlGetFeatures can be used to retrieve the features supported by
	// the vhost implementation in the kernel.
	//
	// Response payload: [virtio.Feature]
	// Kernel name: VHOST_GET_FEATURES
	vhostIoctlGetFeatures = 0x8008af00

	// vhostIoctlSetFeatures can be used to communicate the features supported
	// by this virtio implementation to the kernel.
	//
	// Request payload: [virtio.Feature]
	// Kernel name: VHOST_SET_FEATURES
	vhostIoctlSetFeatures = 0x4008af00

	// vhostIoctlSetOwner can be used to set the current process as the
	// exclusive owner of a control file descriptor.
	//
	// Request payload: none
	// Kernel name: VHOST_SET_OWNER
	vhostIoctlSetOwner = 0x0000af01

	// vhostIoctlSetMemoryLayout can be used to set up or modify the memory
	// layout which describes the IOTLB mappings in the kernel.
	//
	// Request payload: [MemoryLayout] with custom serialization
	// Kernel name: VHOST_SET_MEM_TABLE
	vhostIoctlSetMemoryLayout = 0x4008af03

	// vhostIoctlSetQueueSize can be used to set the size of the virtqueue.
	//
	// Request payload: [QueueState]
	// Kernel name: VHOST_SET_VRING_NUM
	vhostIoctlSetQueueSize = 0x4008af10

	// vhostIoctlSetQueueAddress can be used to set the addresses of the
	// different parts of the virtqueue.
	//
	// Request payload: [QueueAddresses]
	// Kernel name: VHOST_SET_VRING_ADDR
	vhostIoctlSetQueueAddress = 0x4028af11

	// vhostIoctlSetAvailableRingBase can be used to set the index of the next
	// available ring entry the device will process.
	//
	// Request payload: [QueueState]
	// Kernel name: VHOST_SET_VRING_BASE
	vhostIoctlSetAvailableRingBase = 0x4008af12

	// vhostIoctlSetQueueKickEventFD can be used to set the event file
	// descriptor to signal the device when descriptor chains were added to the
	// available ring.
	//
	// Request payload: [QueueFile]
	// Kernel name: VHOST_SET_VRING_KICK
	vhostIoctlSetQueueKickEventFD = 0x4008af20

	// vhostIoctlSetQueueCallEventFD can be used to set the event file
	// descriptor that gets signaled by the device when descriptor chains have
	// been used by it.
	//
	// Request payload: [QueueFile]
	// Kernel name: VHOST_SET_VRING_CALL
	vhostIoctlSetQueueCallEventFD = 0x4008af21
)

// QueueState is an ioctl request payload that can hold a queue index and any
// 32-bit number.
//
// Kernel name: vhost_vring_state
type QueueState struct {
	// QueueIndex is the index of the virtqueue.
	QueueIndex uint32
	// Num is any 32-bit number, depending on the request.
	Num uint32
}

// QueueAddresses is an ioctl request payload that can hold the addresses of the
// different parts of a virtqueue.
//
// Kernel name: vhost_vring_addr
type QueueAddresses struct {
	// QueueIndex is the index of the virtqueue.
	QueueIndex uint32
	// Flags that are not used in this implementation.
	Flags uint32
	// DescriptorTableAddress is the address of the descriptor table in user
	// space memory. It must be 16-byte aligned.
	DescriptorTableAddress uintptr
	// UsedRingAddress is the address of the used ring in user space memory. It
	// must be 4-byte aligned.
	UsedRingAddress uintptr
	// AvailableRingAddress is the address of the available ring in user space
	// memory. It must be 2-byte aligned.
	AvailableRingAddress uintptr
	// LogAddress is used for an optional logging support, not supported by this
	// implementation.
	LogAddress uintptr
}

// QueueFile is an ioctl request payload that can hold a queue index and a file
// descriptor.
//
// Kernel name: vhost_vring_file
type QueueFile struct {
	// QueueIndex is the index of the virtqueue.
	QueueIndex uint32
	// FD is the file descriptor of the file. Pass -1 to unbind from a file.
	FD int32
}

// IoctlPtr is a copy of the similarly named unexported function from the Go
// unix package. This is needed to do custom ioctl requests not supported by the
// standard library.
func IoctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if err != 0 {
		return fmt.Errorf("ioctl request %d: %w", req, err)
	}
	return nil
}

// GetFeatures requests the supported feature bits from the virtio device
// associated with the given control file descriptor.
func GetFeatures(controlFD int) (virtio.Feature, error) {
	var features virtio.Feature
	if err := IoctlPtr(controlFD, vhostIoctlGetFeatures, unsafe.Pointer(&features)); err != nil {
		return 0, fmt.Errorf("get features: %w", err)
	}
	return features, nil
}

// SetFeatures communicates the feature bits supported by this implementation
// to the virtio device associated with the given control file descriptor.
func SetFeatures(controlFD int, features virtio.Feature) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetFeatures, unsafe.Pointer(&features)); err != nil {
		return fmt.Errorf("set features: %w", err)
	}
	return nil
}

// OwnControlFD sets the current process as the exclusive owner for the
// given control file descriptor. This must be called before interacting with
// the control file descriptor in any other way.
func OwnControlFD(controlFD int) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetOwner, unsafe.Pointer(nil)); err != nil {
		return fmt.Errorf("set control file descriptor owner: %w", err)
	}
	return nil
}

// SetMemoryLayout sets up or modifies the memory layout for the kernel-level
// virtio device associated with the given control file descriptor.
func SetMemoryLayout(controlFD int, layout MemoryLayout) error {
	payload := layout.serializePayload()
	if err := IoctlPtr(controlFD, vhostIoctlSetMemoryLayout, unsafe.Pointer(&payload[0])); err != nil {
		return fmt.Errorf("set memory layout: %w", err)
	}
	return nil
}

// RegisterQueue registers a virtio queue with the kernel-level virtio server.
// The virtqueue will be linked to the given control file descriptor and will
// have the given index. The kernel will use this queue until the control file
// descriptor is closed.
func RegisterQueue(controlFD int, queueIndex uint32, queue *virtqueue.SplitQueue) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetQueueSize, unsafe.Pointer(&QueueState{
		QueueIndex: queueIndex,
		Num:        uint32(queue.Size()),
	})); err != nil {
		return fmt.Errorf("set queue size: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueAddress, unsafe.Pointer(&QueueAddresses{
		QueueIndex:             queueIndex,
		Flags:                  0,
		DescriptorTableAddress: queue.DescriptorTable().Address(),
		UsedRingAddress:        queue.UsedRing().Address(),
		AvailableRingAddress:   queue.AvailableRing().Address(),
		LogAddress:             0,
	})); err != nil {
		return fmt.Errorf("set queue addresses: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetAvailableRingBase, unsafe.Pointer(&QueueState{
		QueueIndex: queueIndex,
		Num:        0,
	})); err != nil {
		return fmt.Errorf("set available ring base: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueKickEventFD, unsafe.Pointer(&QueueFile{
		QueueIndex: queueIndex,
		FD:         int32(queue.KickEventFD()),
	})); err != nil {
		return fmt.Errorf("set kick event file descriptor: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueCallEventFD, unsafe.Pointer(&QueueFile{
		QueueIndex: queueIndex,
		FD:         int32(queue.CallEventFD()),
	})); err != nil {
		return fmt.Errorf("set call event file descriptor: %w", err)
	}

	return nil
}
