package virtqueue

import (
	"fmt"
	"unsafe"
)

// availableRingFlag is a flag that describes an [AvailableRing].
type availableRingFlag uint16

const (
	// availableRingFlagNoInterrupt is used by the guest to advise the host to
	// not interrupt it when consuming a buffer. It's unreliable, so it's simply
	// an optimization.
	availableRingFlagNoInterrupt availableRingFlag = 1 << iota
)

// availableRingSize is the number of bytes needed to store an [AvailableRing]
// with the given queue size in memory.
func availableRingSize(queueSize int) int {
	return 6 + 2*queueSize
}

// availableRingAlignment is the minimum alignment of an [AvailableRing]
// in memory, as required by the virtio spec.
const availableRingAlignment = 2

// AvailableRing is used by the driver to offer descriptor chains to the device.
// Each ring entry refers to the head of a descriptor chain. It is only written
// to by the driver and read by the device.
//
// Because the size of the ring depends on the queue size, we cannot define a
// Go struct with a static size that maps to the memory of the ring. Instead,
// this struct only contains pointers to the corresponding memory areas.
type AvailableRing struct {
	initialized bool

	// flags that describe this ring.
	flags *availableRingFlag
	// ringIndex indicates where the driver would put the next entry into the
	// ring (modulo the queue size).
	ringIndex *uint16
	// ring references buffers using the index of the head of the descriptor
	// chain in the [DescriptorTable]. It wraps around at queue size.
	ring []uint16
	// usedEvent is not used by this implementation, but we reserve it anyway to
	// avoid issues in case a device may try to access it, contrary to the
	// virtio specification.
	usedEvent *uint16
}

// newAvailableRing creates an available ring that uses the given underlying
// memory. The length of the memory slice must match the size needed for the
// ring (see [availableRingSize]) for the given queue size.
func newAvailableRing(queueSize int, mem []byte) *AvailableRing {
	ringSize := availableRingSize(queueSize)
	if len(mem) != ringSize {
		panic(fmt.Sprintf("memory size (%v) does not match required size "+
			"for available ring: %v", len(mem), ringSize))
	}

	return &AvailableRing{
		initialized: true,
		flags:       (*availableRingFlag)(unsafe.Pointer(&mem[0])),
		ringIndex:   (*uint16)(unsafe.Pointer(&mem[2])),
		ring:        unsafe.Slice((*uint16)(unsafe.Pointer(&mem[4])), queueSize),
		usedEvent:   (*uint16)(unsafe.Pointer(&mem[ringSize-2])),
	}
}

// Address returns the pointer to the beginning of the ring in memory.
// Do not modify the memory directly to not interfere with this implementation.
func (r *AvailableRing) Address() uintptr {
	if !r.initialized {
		panic("available ring is not initialized")
	}
	return uintptr(unsafe.Pointer(r.flags))
}

// offer adds the given descriptor chain heads to the available ring and
// advances the ring index accordingly to make the device process the new
// descriptor chains.
func (r *AvailableRing) offerElements(chains []UsedElement) {
	//always called under lock
	//r.mu.Lock()
	//defer r.mu.Unlock()

	// Add descriptor chain heads to the ring.
	for offset, x := range chains {
		// The 16-bit ring index may overflow. This is expected and is not an
		// issue because the size of the ring array (which equals the queue
		// size) is always a power of 2 and smaller than the highest possible
		// 16-bit value.
		insertIndex := int(*r.ringIndex+uint16(offset)) % len(r.ring)
		r.ring[insertIndex] = x.GetHead()
	}

	// Increase the ring index by the number of descriptor chains added to the
	// ring.
	*r.ringIndex += uint16(len(chains))
}

func (r *AvailableRing) offer(chains []uint16) {
	//always called under lock
	//r.mu.Lock()
	//defer r.mu.Unlock()

	// Add descriptor chain heads to the ring.
	for offset, x := range chains {
		// The 16-bit ring index may overflow. This is expected and is not an
		// issue because the size of the ring array (which equals the queue
		// size) is always a power of 2 and smaller than the highest possible
		// 16-bit value.
		insertIndex := int(*r.ringIndex+uint16(offset)) % len(r.ring)
		r.ring[insertIndex] = x
	}

	// Increase the ring index by the number of descriptor chains added to the
	// ring.
	*r.ringIndex += uint16(len(chains))
}

func (r *AvailableRing) offerSingle(x uint16) {
	//always called under lock
	//r.mu.Lock()
	//defer r.mu.Unlock()

	offset := 0
	// Add descriptor chain heads to the ring.

	// The 16-bit ring index may overflow. This is expected and is not an
	// issue because the size of the ring array (which equals the queue
	// size) is always a power of 2 and smaller than the highest possible
	// 16-bit value.
	insertIndex := int(*r.ringIndex+uint16(offset)) % len(r.ring)
	r.ring[insertIndex] = x

	// Increase the ring index by the number of descriptor chains added to the ring.
	*r.ringIndex += 1
}
