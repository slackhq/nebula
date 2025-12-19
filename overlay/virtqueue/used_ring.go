package virtqueue

import (
	"fmt"
	"unsafe"
)

// usedRingFlag is a flag that describes a [UsedRing].
type usedRingFlag uint16

const (
	// usedRingFlagNoNotify is used by the host to advise the guest to not
	// kick it when adding a buffer. It's unreliable, so it's simply an
	// optimization. Guest will still kick when it's out of buffers.
	usedRingFlagNoNotify usedRingFlag = 1 << iota
)

// usedRingSize is the number of bytes needed to store a [UsedRing] with the
// given queue size in memory.
func usedRingSize(queueSize int) int {
	return 6 + usedElementSize*queueSize
}

// usedRingAlignment is the minimum alignment of a [UsedRing] in memory, as
// required by the virtio spec.
const usedRingAlignment = 4

// UsedRing is where the device returns descriptor chains once it is done with
// them. Each ring entry is a [UsedElement]. It is only written to by the device
// and read by the driver.
//
// Because the size of the ring depends on the queue size, we cannot define a
// Go struct with a static size that maps to the memory of the ring. Instead,
// this struct only contains pointers to the corresponding memory areas.
type UsedRing struct {
	initialized bool

	// flags that describe this ring.
	flags *usedRingFlag
	// ringIndex indicates where the device would put the next entry into the
	// ring (modulo the queue size).
	ringIndex *uint16
	// ring contains the [UsedElement]s. It wraps around at queue size.
	ring []UsedElement
	// availableEvent is not used by this implementation, but we reserve it
	// anyway to avoid issues in case a device may try to write to it, contrary
	// to the virtio specification.
	availableEvent *uint16

	// lastIndex is the internal ringIndex up to which all [UsedElement]s were
	// processed.
	lastIndex uint16

	//mu sync.Mutex
}

// newUsedRing creates a used ring that uses the given underlying memory. The
// length of the memory slice must match the size needed for the ring (see
// [usedRingSize]) for the given queue size.
func newUsedRing(queueSize int, mem []byte) *UsedRing {
	ringSize := usedRingSize(queueSize)
	if len(mem) != ringSize {
		panic(fmt.Sprintf("memory size (%v) does not match required size "+
			"for used ring: %v", len(mem), ringSize))
	}

	r := UsedRing{
		initialized:    true,
		flags:          (*usedRingFlag)(unsafe.Pointer(&mem[0])),
		ringIndex:      (*uint16)(unsafe.Pointer(&mem[2])),
		ring:           unsafe.Slice((*UsedElement)(unsafe.Pointer(&mem[4])), queueSize),
		availableEvent: (*uint16)(unsafe.Pointer(&mem[ringSize-2])),
	}
	r.lastIndex = *r.ringIndex
	return &r
}

// Address returns the pointer to the beginning of the ring in memory.
// Do not modify the memory directly to not interfere with this implementation.
func (r *UsedRing) Address() uintptr {
	if !r.initialized {
		panic("used ring is not initialized")
	}
	return uintptr(unsafe.Pointer(r.flags))
}

func (r *UsedRing) availableToTake() int {
	ringIndex := *r.ringIndex
	if ringIndex == r.lastIndex {
		// Nothing new.
		return 0
	}

	// Calculate the number new used elements that we can read from the ring.
	// The ring index may wrap, so special handling for that case is needed.
	count := int(ringIndex - r.lastIndex)
	if count < 0 {
		count += 0xffff
	}
	return count
}

// take returns all new [UsedElement]s that the device put into the ring and
// that weren't already returned by a previous call to this method.
func (r *UsedRing) take(maxToTake int) (int, []UsedElement) {
	count := r.availableToTake()
	if count == 0 {
		return 0, nil
	}

	stillNeedToTake := 0

	if maxToTake > 0 {
		stillNeedToTake = count - maxToTake
		if stillNeedToTake < 0 {
			stillNeedToTake = 0
		}
		count = min(count, maxToTake)
	}

	// The number of new elements can never exceed the queue size.
	if count > len(r.ring) {
		panic("used ring contains more new elements than the ring is long")
	}

	elems := make([]UsedElement, count)
	for i := range count {
		elems[i] = r.ring[r.lastIndex%uint16(len(r.ring))]
		r.lastIndex++
	}

	return stillNeedToTake, elems
}

func (r *UsedRing) takeOne() (UsedElement, bool) {
	//r.mu.Lock()
	//defer r.mu.Unlock()

	count := r.availableToTake()
	if count == 0 {
		return UsedElement{}, false
	}

	// The number of new elements can never exceed the queue size.
	if count > len(r.ring) {
		panic("used ring contains more new elements than the ring is long")
	}

	out := r.ring[r.lastIndex%uint16(len(r.ring))]
	r.lastIndex++

	return out, true
}

// InitOfferSingle is only used to pre-fill the used queue at startup, and should not be used if the device is running!
func (r *UsedRing) InitOfferSingle(x uint16, size uint32) {
	offset := 0
	// Add descriptor chain heads to the ring.

	// The 16-bit ring index may overflow. This is expected and is not an
	// issue because the size of the ring array (which equals the queue
	// size) is always a power of 2 and smaller than the highest possible
	// 16-bit value.
	insertIndex := int(*r.ringIndex+uint16(offset)) % len(r.ring)
	r.ring[insertIndex].DescriptorIndex = uint32(x)
	r.ring[insertIndex].Length = size

	// Increase the ring index by the number of descriptor chains added to the ring.
	*r.ringIndex += 1
}
