package vhost

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/slackhq/nebula/overlay/virtqueue"
)

// MemoryRegion describes a region of userspace memory which is being made
// accessible to a vhost device.
//
// Kernel name: vhost_memory_region
type MemoryRegion struct {
	// GuestPhysicalAddress is the physical address of the memory region within
	// the guest, when virtualization is used. When no virtualization is used,
	// this should be the same as UserspaceAddress.
	GuestPhysicalAddress uintptr
	// Size is the size of the memory region.
	Size uint64
	// UserspaceAddress is the virtual address in the userspace of the host
	// where the memory region can be found.
	UserspaceAddress uintptr
	// Padding and room for flags. Currently unused.
	_ uint64
}

// MemoryLayout is a list of [MemoryRegion]s.
type MemoryLayout []MemoryRegion

// NewMemoryLayoutForQueues returns a new [MemoryLayout] that describes the
// memory pages used by the descriptor tables of the given queues.
func NewMemoryLayoutForQueues(queues []*virtqueue.SplitQueue) MemoryLayout {
	regions := make([]MemoryRegion, 0)
	for _, queue := range queues {
		for address, size := range queue.DescriptorTable().BufferAddresses() {
			regions = append(regions, MemoryRegion{
				// There is no virtualization in play here, so the guest address
				// is the same as in the host's userspace.
				GuestPhysicalAddress: address,
				Size:                 uint64(size),
				UserspaceAddress:     address,
			})
		}
	}
	return regions
}

// serializePayload serializes the list of memory regions into a format that is
// compatible to the vhost_memory kernel struct. The returned byte slice can be
// used as a payload for the vhostIoctlSetMemoryLayout ioctl.
func (regions MemoryLayout) serializePayload() []byte {
	regionCount := len(regions)
	regionSize := int(unsafe.Sizeof(MemoryRegion{}))
	payload := make([]byte, 8+regionCount*regionSize)

	// The first 32 bits contain the number of memory regions. The following 32
	// bits are padding.
	binary.LittleEndian.PutUint32(payload[0:4], uint32(regionCount))

	if regionCount > 0 {
		// The underlying byte array of the slice should already have the correct
		// format, so just copy that.
		copied := copy(payload[8:], unsafe.Slice((*byte)(unsafe.Pointer(&regions[0])), regionCount*regionSize))
		if copied != regionCount*regionSize {
			panic(fmt.Sprintf("copied only %d bytes of the memory regions, but expected %d",
				copied, regionCount*regionSize))
		}
	}

	return payload
}
