package virtqueue

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/slackhq/nebula/overlay/eventfd"
	"golang.org/x/sys/unix"
)

// SplitQueue is a virtqueue that consists of several parts, where each part is
// writeable by either the driver or the device, but not both.
type SplitQueue struct {
	// size is the size of the queue.
	size int
	// buf is the underlying memory used for the queue.
	buf []byte

	descriptorTable *DescriptorTable
	availableRing   *AvailableRing
	usedRing        *UsedRing

	// kickEventFD is used to signal the device when descriptor chains were
	// added to the available ring.
	kickEventFD eventfd.EventFD
	// callEventFD is used by the device to signal when it has used descriptor
	// chains and put them in the used ring.
	callEventFD eventfd.EventFD

	// stop is used by [SplitQueue.Close] to cancel the goroutine that handles
	// used buffer notifications. It blocks until the goroutine ended.
	stop func() error

	itemSize int

	epoll eventfd.Epoll
	more  int
}

// NewSplitQueue allocates a new [SplitQueue] in memory. The given queue size
// specifies the number of entries/buffers the queue can hold. This also affects
// the memory consumption.
func NewSplitQueue(queueSize int, itemSize int) (_ *SplitQueue, err error) {
	if err = CheckQueueSize(queueSize); err != nil {
		return nil, err
	}

	if itemSize%os.Getpagesize() != 0 {
		return nil, errors.New("split queue size must be multiple of os.Getpagesize()")
	}

	sq := SplitQueue{
		size:     queueSize,
		itemSize: itemSize,
	}

	// Clean up a partially initialized queue when something fails.
	defer func() {
		if err != nil {
			_ = sq.Close()
		}
	}()

	// There are multiple ways for how the memory for the virtqueue could be
	// allocated. We could use Go native structs with arrays inside them, but
	// this wouldn't allow us to make the queue size configurable. And including
	// a slice in the Go structs wouldn't work, because this would just put the
	// Go slice descriptor into the memory region which the virtio device will
	// not understand.
	// Additionally, Go does not allow us to ensure a correct alignment of the
	// parts of the virtqueue, as it is required by the virtio specification.
	//
	// To resolve this, let's just allocate the memory manually by allocating
	// one or more memory pages, depending on the queue size. Making the
	// virtqueue start at the beginning of a page is not strictly necessary, as
	// the virtio specification does not require it to be continuous in the
	// physical memory of the host (e.g. the vhost implementation in the kernel
	// always uses copy_from_user to access it), but this makes it very easy to
	// guarantee the alignment. Also, it is not required for the virtqueue parts
	// to be in the same memory region, as we pass separate pointers to them to
	// the device, but this design just makes things easier to implement.
	//
	// One added benefit of allocating the memory manually is, that we have full
	// control over its lifetime and don't risk the garbage collector to collect
	// our valuable structures while the device still works with them.

	// The descriptor table is at the start of the page, so alignment is not an
	// issue here.
	descriptorTableStart := 0
	descriptorTableEnd := descriptorTableStart + descriptorTableSize(queueSize)
	availableRingStart := align(descriptorTableEnd, availableRingAlignment)
	availableRingEnd := availableRingStart + availableRingSize(queueSize)
	usedRingStart := align(availableRingEnd, usedRingAlignment)
	usedRingEnd := usedRingStart + usedRingSize(queueSize)

	sq.buf, err = unix.Mmap(-1, 0, usedRingEnd,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("allocate virtqueue buffer: %w", err)
	}

	sq.descriptorTable = newDescriptorTable(queueSize, sq.buf[descriptorTableStart:descriptorTableEnd], sq.itemSize)
	sq.availableRing = newAvailableRing(queueSize, sq.buf[availableRingStart:availableRingEnd])
	sq.usedRing = newUsedRing(queueSize, sq.buf[usedRingStart:usedRingEnd])

	sq.kickEventFD, err = eventfd.New()
	if err != nil {
		return nil, fmt.Errorf("create kick event file descriptor: %w", err)
	}
	sq.callEventFD, err = eventfd.New()
	if err != nil {
		return nil, fmt.Errorf("create call event file descriptor: %w", err)
	}

	if err = sq.descriptorTable.initializeDescriptors(); err != nil {
		return nil, fmt.Errorf("initialize descriptors: %w", err)
	}

	sq.epoll, err = eventfd.NewEpoll()
	if err != nil {
		return nil, err
	}
	err = sq.epoll.AddEvent(sq.callEventFD.FD())
	if err != nil {
		return nil, err
	}

	sq.stop = sq.kickSelfToExit()

	return &sq, nil
}

// Size returns the size of this queue, which is the number of entries/buffers
// this queue can hold.
func (sq *SplitQueue) Size() int {
	return sq.size
}

// DescriptorTable returns the [DescriptorTable] behind this queue.
func (sq *SplitQueue) DescriptorTable() *DescriptorTable {
	return sq.descriptorTable
}

// AvailableRing returns the [AvailableRing] behind this queue.
func (sq *SplitQueue) AvailableRing() *AvailableRing {
	return sq.availableRing
}

// UsedRing returns the [UsedRing] behind this queue.
func (sq *SplitQueue) UsedRing() *UsedRing {
	return sq.usedRing
}

// KickEventFD returns the kick event file descriptor behind this queue.
// The returned file descriptor should be used with great care to not interfere
// with this implementation.
func (sq *SplitQueue) KickEventFD() int {
	return sq.kickEventFD.FD()
}

// CallEventFD returns the call event file descriptor behind this queue.
// The returned file descriptor should be used with great care to not interfere
// with this implementation.
func (sq *SplitQueue) CallEventFD() int {
	return sq.callEventFD.FD()
}

func (sq *SplitQueue) kickSelfToExit() func() error {
	return func() error {

		// The goroutine blocks until it receives a signal on the event file
		// descriptor, so it will never notice the context being canceled.
		// To resolve this, we can just produce a fake-signal ourselves to wake
		// it up.
		if err := sq.callEventFD.Kick(); err != nil {
			return fmt.Errorf("wake up goroutine: %w", err)
		}
		return nil
	}
}

func (sq *SplitQueue) TakeSingleIndex(ctx context.Context) (uint16, error) {
	element, err := sq.TakeSingle(ctx)
	if err != nil {
		return 0xffff, err
	}
	return element.GetHead(), nil
}

func (sq *SplitQueue) TakeSingle(ctx context.Context) (UsedElement, error) {
	var n int
	var err error
	for ctx.Err() == nil {
		out, ok := sq.usedRing.takeOne()
		if ok {
			return out, nil
		}
		// Wait for a signal from the device.
		if n, err = sq.epoll.Block(); err != nil {
			return UsedElement{}, fmt.Errorf("wait: %w", err)
		}

		if n > 0 {
			out, ok = sq.usedRing.takeOne()
			if ok {
				_ = sq.epoll.Clear() //???
				return out, nil
			} else {
				continue //???
			}
		}
	}
	return UsedElement{}, ctx.Err()
}

func (sq *SplitQueue) TakeSingleNoBlock() (UsedElement, bool) {
	return sq.usedRing.takeOne()
}

func (sq *SplitQueue) WaitForUsedElements(ctx context.Context) error {
	if sq.usedRing.availableToTake() != 0 {
		return nil
	}
	for ctx.Err() == nil {
		// Wait for a signal from the device.
		n, err := sq.epoll.Block()
		if err != nil {
			return fmt.Errorf("wait: %w", err)
		}
		if n > 0 {
			_ = sq.epoll.Clear()
			if sq.usedRing.availableToTake() != 0 {
				return nil
			}
		}
	}
	return ctx.Err()
}

func (sq *SplitQueue) BlockAndGetHeadsCapped(ctx context.Context, maxToTake int) ([]UsedElement, error) {
	var n int
	var err error
	for ctx.Err() == nil {

		//we have leftovers in the fridge
		if sq.more > 0 {
			stillNeedToTake, out := sq.usedRing.take(maxToTake)
			sq.more = stillNeedToTake
			return out, nil
		}
		//look inside the fridge
		stillNeedToTake, out := sq.usedRing.take(maxToTake)
		if len(out) > 0 {
			sq.more = stillNeedToTake
			return out, nil
		}
		//fridge is empty I guess

		// Wait for a signal from the device.
		if n, err = sq.epoll.Block(); err != nil {
			return nil, fmt.Errorf("wait: %w", err)
		}
		if n > 0 {
			_ = sq.epoll.Clear()
			stillNeedToTake, out = sq.usedRing.take(maxToTake)
			sq.more = stillNeedToTake
			return out, nil
		}
	}

	return nil, ctx.Err()
}

// OfferDescriptorChain offers a descriptor chain to the device which contains a
// number of device-readable buffers (out buffers) and device-writable buffers
// (in buffers).
//
// All buffers in the outBuffers slice will be concatenated by chaining
// descriptors, one for each buffer in the slice. When a buffer is too large to
// fit into a single descriptor (limited by the system's page size), it will be
// split up into multiple descriptors within the chain.
// When numInBuffers is greater than zero, the given number of device-writable
// descriptors will be appended to the end of the chain, each referencing a
// whole memory page (see [os.Getpagesize]).
//
// When the queue is full and no more descriptor chains can be added, a wrapped
// [ErrNotEnoughFreeDescriptors] will be returned. If you set waitFree to true,
// this method will handle this error and will block instead until there are
// enough free descriptors again.
//
// After defining the descriptor chain in the [DescriptorTable], the index of
// the head of the chain will be made available to the device using the
// [AvailableRing] and will be returned by this method.
// Callers should read from the [SplitQueue.UsedDescriptorChains] channel to be
// notified when the descriptor chain was used by the device and should free the
// used descriptor chains again using [SplitQueue.FreeDescriptorChain] when
// they're done with them. When this does not happen, the queue will run full
// and any further calls to [SplitQueue.OfferDescriptorChain] will stall.

func (sq *SplitQueue) OfferInDescriptorChains() (uint16, error) {
	// Create a descriptor chain for the given buffers.
	var (
		head uint16
		err  error
	)
	for {
		head, err = sq.descriptorTable.createDescriptorForInputs()
		if err == nil {
			break
		}

		// I don't wanna use errors.Is, it's slow
		//goland:noinspection GoDirectComparisonOfErrors
		if err == ErrNotEnoughFreeDescriptors {
			return 0, err
		} else {
			return 0, fmt.Errorf("create descriptor chain: %w", err)
		}
	}

	// Make the descriptor chain available to the device.
	sq.availableRing.offerSingle(head)

	// Notify the device to make it process the updated available ring.
	if err = sq.kickEventFD.Kick(); err != nil {
		return head, fmt.Errorf("notify device: %w", err)
	}

	return head, nil
}

// GetDescriptorItem returns the buffer of a given index
// The head index must be one that was returned by a previous call to
// [SplitQueue.OfferDescriptorChain] and the descriptor chain must not have been
// freed yet.
//
// Be careful to only access the returned buffer slices when the device is no
// longer using them. They must not be accessed after
// [SplitQueue.FreeDescriptorChain] has been called.
func (sq *SplitQueue) GetDescriptorItem(head uint16) ([]byte, error) {
	sq.descriptorTable.descriptors[head].length = uint32(sq.descriptorTable.itemSize)
	return sq.descriptorTable.getDescriptorItem(head)
}

func (sq *SplitQueue) SetDescSize(head uint16, sz int) {
	//not called under lock
	sq.descriptorTable.descriptors[int(head)].length = uint32(sz)
}

func (sq *SplitQueue) OfferDescriptorChains(chains []uint16, kick bool) error {
	//todo not doing this may break eventually?
	//not called under lock
	//if err := sq.descriptorTable.freeDescriptorChain(head); err != nil {
	//	return fmt.Errorf("free: %w", err)
	//}

	// Make the descriptor chain available to the device.
	sq.availableRing.offer(chains)

	// Notify the device to make it process the updated available ring.
	if kick {
		return sq.Kick()
	}

	return nil
}

func (sq *SplitQueue) Kick() error {
	if err := sq.kickEventFD.Kick(); err != nil {
		return fmt.Errorf("notify device: %w", err)
	}
	return nil
}

// Close releases all resources used for this queue.
// The implementation will try to release as many resources as possible and
// collect potential errors before returning them.
func (sq *SplitQueue) Close() error {
	var errs []error

	if sq.stop != nil {
		// This has to happen before the event file descriptors may be closed.
		if err := sq.stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop consume used ring: %w", err))
		}

		// Make sure that this code block is executed only once.
		sq.stop = nil
	}

	if err := sq.kickEventFD.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close kick event file descriptor: %w", err))
	}
	if err := sq.callEventFD.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close call event file descriptor: %w", err))
	}

	if err := sq.descriptorTable.releaseBuffers(); err != nil {
		errs = append(errs, fmt.Errorf("release descriptor buffers: %w", err))
	}

	if sq.buf != nil {
		if err := unix.Munmap(sq.buf); err == nil {
			sq.buf = nil
		} else {
			errs = append(errs, fmt.Errorf("unmap virtqueue buffer: %w", err))
		}
	}

	return errors.Join(errs...)
}

func align(index, alignment int) int {
	remainder := index % alignment
	if remainder == 0 {
		return index
	}
	return index + alignment - remainder
}
