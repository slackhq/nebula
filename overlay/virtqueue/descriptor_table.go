package virtqueue

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	// ErrDescriptorChainEmpty is returned when a descriptor chain would contain
	// no buffers, which is not allowed.
	ErrDescriptorChainEmpty = errors.New("empty descriptor chains are not allowed")

	// ErrNotEnoughFreeDescriptors is returned when the free descriptors are
	// exhausted, meaning that the queue is full.
	ErrNotEnoughFreeDescriptors = errors.New("not enough free descriptors, queue is full")

	// ErrInvalidDescriptorChain is returned when a descriptor chain is not
	// valid for a given operation.
	ErrInvalidDescriptorChain = errors.New("invalid descriptor chain")
)

// noFreeHead is used to mark when all descriptors are in use and we have no
// free chain. This value is impossible to occur as an index naturally, because
// it exceeds the maximum queue size.
const noFreeHead = uint16(math.MaxUint16)

// descriptorTableSize is the number of bytes needed to store a
// [DescriptorTable] with the given queue size in memory.
func descriptorTableSize(queueSize int) int {
	return descriptorSize * queueSize
}

// descriptorTableAlignment is the minimum alignment of a [DescriptorTable]
// in memory, as required by the virtio spec.
const descriptorTableAlignment = 16

// DescriptorTable is a table that holds [Descriptor]s, addressed via their
// index in the slice.
type DescriptorTable struct {
	descriptors []Descriptor

	// freeHeadIndex is the index of the head of the descriptor chain which
	// contains all currently unused descriptors. When all descriptors are in
	// use, this has the special value of noFreeHead.
	freeHeadIndex uint16
	// freeNum tracks the number of descriptors which are currently not in use.
	freeNum uint16

	bufferBase uintptr
	bufferSize int
	itemSize   int
}

// newDescriptorTable creates a descriptor table that uses the given underlying
// memory. The Length of the memory slice must match the size needed for the
// descriptor table (see [descriptorTableSize]) for the given queue size.
//
// Before this descriptor table can be used, [initialize] must be called.
func newDescriptorTable(queueSize int, mem []byte, itemSize int) *DescriptorTable {
	dtSize := descriptorTableSize(queueSize)
	if len(mem) != dtSize {
		panic(fmt.Sprintf("memory size (%v) does not match required size "+
			"for descriptor table: %v", len(mem), dtSize))
	}

	return &DescriptorTable{
		descriptors: unsafe.Slice((*Descriptor)(unsafe.Pointer(&mem[0])), queueSize),
		// We have no free descriptors until they were initialized.
		freeHeadIndex: noFreeHead,
		freeNum:       0,
		itemSize:      itemSize, //todo configurable? needs to be page-aligned
	}
}

// Address returns the pointer to the beginning of the descriptor table in
// memory. Do not modify the memory directly to not interfere with this
// implementation.
func (dt *DescriptorTable) Address() uintptr {
	if dt.descriptors == nil {
		panic("descriptor table is not initialized")
	}
	//should be same as dt.bufferBase
	return uintptr(unsafe.Pointer(&dt.descriptors[0]))
}

func (dt *DescriptorTable) Size() uintptr {
	if dt.descriptors == nil {
		panic("descriptor table is not initialized")
	}
	return uintptr(dt.bufferSize)
}

// BufferAddresses returns a map of pointer->size for all allocations used by the table
func (dt *DescriptorTable) BufferAddresses() map[uintptr]int {
	if dt.descriptors == nil {
		panic("descriptor table is not initialized")
	}

	return map[uintptr]int{dt.bufferBase: dt.bufferSize}
}

// initializeDescriptors allocates buffers with the size of a full memory page
// for each descriptor in the table. While this may be a bit wasteful, it makes
// dealing with descriptors way easier. Without this preallocation, we would
// have to allocate and free memory on demand, increasing complexity.
//
// All descriptors will be marked as free and will form a free chain. The
// addresses of all descriptors will be populated while their length remains
// zero.
func (dt *DescriptorTable) initializeDescriptors() error {
	numDescriptors := len(dt.descriptors)

	// Allocate ONE large region for all buffers
	totalSize := dt.itemSize * numDescriptors
	basePtr, err := unix.MmapPtr(-1, 0, nil, uintptr(totalSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("allocate buffer memory for descriptors: %w", err)
	}

	// Store the base for cleanup later
	dt.bufferBase = uintptr(basePtr)
	dt.bufferSize = totalSize

	for i := range dt.descriptors {
		dt.descriptors[i] = Descriptor{
			address: dt.bufferBase + uintptr(i*dt.itemSize),
			length:  0,
			// All descriptors should form a free chain that loops around.
			flags: descriptorFlagHasNext,
			next:  uint16((i + 1) % len(dt.descriptors)),
		}
	}

	// All descriptors are free to use now.
	dt.freeHeadIndex = 0
	dt.freeNum = uint16(len(dt.descriptors))

	return nil
}

// releaseBuffers releases all allocated buffers for this descriptor table.
// The implementation will try to release as many buffers as possible and
// collect potential errors before returning them.
// The descriptor table should no longer be used after calling this.
func (dt *DescriptorTable) releaseBuffers() error {
	for i := range dt.descriptors {
		descriptor := &dt.descriptors[i]
		descriptor.address = 0
	}

	// As a safety measure, make sure no descriptors can be used anymore.
	dt.freeHeadIndex = noFreeHead
	dt.freeNum = 0

	if dt.bufferBase != 0 {
		// The pointer points to memory not managed by Go, so this conversion
		// is safe. See https://github.com/golang/go/issues/58625
		dt.bufferBase = 0
		//goland:noinspection GoVetUnsafePointer
		err := unix.MunmapPtr(unsafe.Pointer(dt.bufferBase), uintptr(dt.bufferSize))
		if err != nil {
			return fmt.Errorf("release buffer memory: %w", err)
		}
	}

	return nil
}

func (dt *DescriptorTable) CreateDescriptorForOutputs() (uint16, error) {
	//todo just fill the damn table
	// Do we still have enough free descriptors?

	if 1 > dt.freeNum {
		return 0, ErrNotEnoughFreeDescriptors
	}

	// Above validation ensured that there is at least one free descriptor, so
	// the free descriptor chain head should be valid.
	if dt.freeHeadIndex == noFreeHead {
		panic("free descriptor chain head is unset but there should be free descriptors")
	}

	// To avoid having to iterate over the whole table to find the descriptor
	// pointing to the head just to replace the free head, we instead always
	// create descriptor chains from the descriptors coming after the head.
	// This way we only have to touch the head as a last resort, when all other
	// descriptors are already used.
	head := dt.descriptors[dt.freeHeadIndex].next
	desc := &dt.descriptors[head]
	next := desc.next

	checkUnusedDescriptorLength(head, desc)

	// Give the device the maximum available number of bytes to write into.
	desc.length = uint32(dt.itemSize)
	desc.flags = 0 // descriptorFlagWritable
	desc.next = 0  // Not necessary to clear this, it's just for looks.

	dt.freeNum -= 1

	if dt.freeNum == 0 {
		// The last descriptor in the chain should be the free chain head
		// itself.
		if next != dt.freeHeadIndex {
			panic("descriptor chain takes up all free descriptors but does not end with the free chain head")
		}

		// When this new chain takes up all remaining descriptors, we no longer
		// have a free chain.
		dt.freeHeadIndex = noFreeHead
	} else {
		// We took some descriptors out of the free chain, so make sure to close
		// the circle again.
		dt.descriptors[dt.freeHeadIndex].next = next
	}

	return head, nil
}

func (dt *DescriptorTable) createDescriptorForInputs() (uint16, error) {
	// Do we still have enough free descriptors?
	if 1 > dt.freeNum {
		return 0, ErrNotEnoughFreeDescriptors
	}

	// Above validation ensured that there is at least one free descriptor, so
	// the free descriptor chain head should be valid.
	if dt.freeHeadIndex == noFreeHead {
		panic("free descriptor chain head is unset but there should be free descriptors")
	}

	// To avoid having to iterate over the whole table to find the descriptor
	// pointing to the head just to replace the free head, we instead always
	// create descriptor chains from the descriptors coming after the head.
	// This way we only have to touch the head as a last resort, when all other
	// descriptors are already used.
	head := dt.descriptors[dt.freeHeadIndex].next
	desc := &dt.descriptors[head]
	next := desc.next

	checkUnusedDescriptorLength(head, desc)

	// Give the device the maximum available number of bytes to write into.
	desc.length = uint32(dt.itemSize)
	desc.flags = descriptorFlagWritable
	desc.next = 0 // Not necessary to clear this, it's just for looks.

	dt.freeNum -= 1

	if dt.freeNum == 0 {
		// The last descriptor in the chain should be the free chain head
		// itself.
		if next != dt.freeHeadIndex {
			panic("descriptor chain takes up all free descriptors but does not end with the free chain head")
		}

		// When this new chain takes up all remaining descriptors, we no longer
		// have a free chain.
		dt.freeHeadIndex = noFreeHead
	} else {
		// We took some descriptors out of the free chain, so make sure to close
		// the circle again.
		dt.descriptors[dt.freeHeadIndex].next = next
	}

	return head, nil
}

// TODO: Implement a zero-copy variant of createDescriptorChain?

// getDescriptorChain returns the device-readable buffers (out buffers) and
// device-writable buffers (in buffers) of the descriptor chain that starts with
// the given head index. The descriptor chain must have been created using
// [createDescriptorChain] and must not have been freed yet (meaning that the
// head index must not be contained in the free chain).
//
// Be careful to only access the returned buffer slices when the device has not
// yet or is no longer using them. They must not be accessed after
// [freeDescriptorChain] has been called.
func (dt *DescriptorTable) getDescriptorChain(head uint16) (outBuffers, inBuffers [][]byte, err error) {
	if int(head) > len(dt.descriptors) {
		return nil, nil, fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	// Iterate over the chain. The iteration is limited to the queue size to
	// avoid ending up in an endless loop when things go very wrong.
	next := head
	for range len(dt.descriptors) {
		if next == dt.freeHeadIndex {
			return nil, nil, fmt.Errorf("%w: must not be part of the free chain", ErrInvalidDescriptorChain)
		}

		desc := &dt.descriptors[next]

		// The descriptor address points to memory not managed by Go, so this
		// conversion is safe. See https://github.com/golang/go/issues/58625
		//goland:noinspection GoVetUnsafePointer
		bs := unsafe.Slice((*byte)(unsafe.Pointer(desc.address)), desc.length)

		if desc.flags&descriptorFlagWritable == 0 {
			outBuffers = append(outBuffers, bs)
		} else {
			inBuffers = append(inBuffers, bs)
		}

		// Is this the tail of the chain?
		if desc.flags&descriptorFlagHasNext == 0 {
			break
		}

		// Detect loops.
		if desc.next == head {
			return nil, nil, fmt.Errorf("%w: contains a loop", ErrInvalidDescriptorChain)
		}

		next = desc.next
	}

	return
}

func (dt *DescriptorTable) getDescriptorItem(head uint16) ([]byte, error) {
	if int(head) > len(dt.descriptors) {
		return nil, fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	desc := &dt.descriptors[head] //todo this is a pretty nasty hack with no checks

	// The descriptor address points to memory not managed by Go, so this
	// conversion is safe. See https://github.com/golang/go/issues/58625
	//goland:noinspection GoVetUnsafePointer
	bs := unsafe.Slice((*byte)(unsafe.Pointer(desc.address)), desc.length)
	return bs, nil
}

func (dt *DescriptorTable) getDescriptorInbuffers(head uint16, inBuffers *[][]byte) error {
	if int(head) > len(dt.descriptors) {
		return fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	// Iterate over the chain. The iteration is limited to the queue size to
	// avoid ending up in an endless loop when things go very wrong.
	next := head
	for range len(dt.descriptors) {
		if next == dt.freeHeadIndex {
			return fmt.Errorf("%w: must not be part of the free chain", ErrInvalidDescriptorChain)
		}

		desc := &dt.descriptors[next]

		// The descriptor address points to memory not managed by Go, so this
		// conversion is safe. See https://github.com/golang/go/issues/58625
		//goland:noinspection GoVetUnsafePointer
		bs := unsafe.Slice((*byte)(unsafe.Pointer(desc.address)), desc.length)

		if desc.flags&descriptorFlagWritable == 0 {
			return fmt.Errorf("there should not be an outbuffer in %d", head)
		} else {
			*inBuffers = append(*inBuffers, bs)
		}

		// Is this the tail of the chain?
		if desc.flags&descriptorFlagHasNext == 0 {
			break
		}

		// Detect loops.
		if desc.next == head {
			return fmt.Errorf("%w: contains a loop", ErrInvalidDescriptorChain)
		}

		next = desc.next
	}

	return nil
}

// freeDescriptorChain can be used to free a descriptor chain when it is no
// longer in use. The descriptor chain that starts with the given index will be
// put back into the free chain, so the descriptors can be used for later calls
// of [createDescriptorChain].
// The descriptor chain must have been created using [createDescriptorChain] and
// must not have been freed yet (meaning that the head index must not be
// contained in the free chain).
func (dt *DescriptorTable) freeDescriptorChain(head uint16) error {
	if int(head) > len(dt.descriptors) {
		return fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	// Iterate over the chain. The iteration is limited to the queue size to
	// avoid ending up in an endless loop when things go very wrong.
	next := head
	var tailDesc *Descriptor
	var chainLen uint16
	for range len(dt.descriptors) {
		if next == dt.freeHeadIndex {
			return fmt.Errorf("%w: must not be part of the free chain", ErrInvalidDescriptorChain)
		}

		desc := &dt.descriptors[next]
		chainLen++

		// Set the length of all unused descriptors back to zero.
		desc.length = 0

		// Unset all flags except the next flag.
		desc.flags &= descriptorFlagHasNext

		// Is this the tail of the chain?
		if desc.flags&descriptorFlagHasNext == 0 {
			tailDesc = desc
			break
		}

		// Detect loops.
		if desc.next == head {
			return fmt.Errorf("%w: contains a loop", ErrInvalidDescriptorChain)
		}

		next = desc.next
	}
	if tailDesc == nil {
		// A descriptor chain longer than the queue size but without loops
		// should be impossible.
		panic(fmt.Sprintf("could not find a tail for descriptor chain starting at %d", head))
	}

	// The tail descriptor does not have the next flag set, but when it comes
	// back into the free chain, it should have.
	tailDesc.flags = descriptorFlagHasNext

	if dt.freeHeadIndex == noFreeHead {
		// The whole free chain was used up, so we turn this returned descriptor
		// chain into the new free chain by completing the circle and using its
		// head.
		tailDesc.next = head
		dt.freeHeadIndex = head
	} else {
		// Attach the returned chain at the beginning of the free chain but
		// right after the free chain head.
		freeHeadDesc := &dt.descriptors[dt.freeHeadIndex]
		tailDesc.next = freeHeadDesc.next
		freeHeadDesc.next = head
	}

	dt.freeNum += chainLen

	return nil
}

// checkUnusedDescriptorLength asserts that the length of an unused descriptor
// is zero, as it should be.
// This is not a requirement by the virtio spec but rather a thing we do to
// notice when our algorithm goes sideways.
func checkUnusedDescriptorLength(index uint16, desc *Descriptor) {
	if desc.length != 0 {
		panic(fmt.Sprintf("descriptor %d should be unused but has a non-zero length", index))
	}
}
