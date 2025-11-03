//go:build linux && !android && !e2e_testing
// +build linux,!android,!e2e_testing

package udp

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	ioringOpSendmsg              = 9
	ioringOpRecvmsg              = 10
	ioringEnterGetevents         = 1 << 0
	ioringSetupClamp             = 1 << 4
	ioringSetupCoopTaskrun       = 1 << 8  // Kernel 5.19+: reduce thread creation
	ioringSetupSingleIssuer      = 1 << 12 // Kernel 6.0+: single submitter optimization
	ioringRegisterIowqMaxWorkers = 19      // Register opcode to limit workers
	ioringOffSqRing              = 0
	ioringOffCqRing              = 0x8000000
	ioringOffSqes                = 0x10000000
	defaultIoUringEntries        = 256
	ioUringSqeSize               = 64 // struct io_uring_sqe size defined by kernel ABI
)

type ioSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

type ioCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Resv        [2]uint32
}

type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        ioSqringOffsets
	CqOff        ioCqringOffsets
}

type ioUringSqe struct {
	Opcode      uint8
	Flags       uint8
	Ioprio      uint16
	Fd          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	MsgFlags    uint32
	UserData    uint64
	BufIndex    uint16
	Personality uint16
	SpliceFdIn  int32
	SpliceOffIn uint64
	Addr2       uint64
}

type ioUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
	// No explicit padding needed - Go will align uint64 to 8 bytes,
	// and int32/uint32 will be naturally aligned. Total size should be 16 bytes.
	// Kernel structure: __u64 user_data; __s32 res; __u32 flags;
}

func init() {
	if sz := unsafe.Sizeof(ioUringSqe{}); sz != ioUringSqeSize {
		panic(fmt.Sprintf("io_uring SQE size mismatch: expected %d, got %d", ioUringSqeSize, sz))
	}
	if sz := unsafe.Sizeof(ioUringCqe{}); sz != 16 {
		panic(fmt.Sprintf("io_uring CQE size mismatch: expected %d, got %d", 16, sz))
	}
}

// pendingSend tracks all heap-allocated structures for a single io_uring submission
// to ensure they remain valid until the kernel completes the operation
type pendingSend struct {
	msgCopy      *unix.Msghdr
	iovCopy      *unix.Iovec
	sockaddrCopy []byte
	controlCopy  []byte
	payloadRef   unsafe.Pointer
	userData     uint64
}

type pendingRecv struct {
	msgCopy    *unix.Msghdr
	iovCopy    *unix.Iovec
	nameBuf    []byte
	controlBuf []byte
	payloadBuf []byte
	callerMsg  *unix.Msghdr
	userData   uint64
}

type ioUringBatchResult struct {
	res   int32
	flags uint32
	err   error
}

type ioUringBatchEntry struct {
	fd         int
	msg        *unix.Msghdr
	msgFlags   uint32
	payloadLen uint32
	userData   uint64
	result     *ioUringBatchResult
}

type ioUringState struct {
	fd      int
	sqRing  []byte
	cqRing  []byte
	sqesMap []byte
	sqes    []ioUringSqe
	cqCqes  []ioUringCqe

	sqHead        *uint32
	sqTail        *uint32
	sqRingMask    *uint32
	sqRingEntries *uint32
	sqArray       []uint32

	cqHead        *uint32
	cqTail        *uint32
	cqRingMask    *uint32
	cqRingEntries *uint32

	mu           sync.Mutex
	userData     uint64
	pendingSends map[uint64]*pendingSend

	sqEntryCount uint32
	cqEntryCount uint32

	pendingReceives map[uint64]*pendingRecv
	completedCqes   map[uint64]*ioUringCqe
}

// recvBuffer represents a single receive operation with its associated buffers
type recvBuffer struct {
	payloadBuf []byte       // Buffer for packet data
	nameBuf    []byte       // Buffer for source address
	controlBuf []byte       // Buffer for control messages
	msghdr     *unix.Msghdr // Message header for recvmsg
	iovec      *unix.Iovec  // IO vector pointing to payloadBuf
	userData   uint64       // User data for tracking this operation
	inFlight   atomic.Bool  // Whether this buffer has a pending io_uring operation
}

// ioUringRecvState manages a dedicated io_uring for receiving packets
// It maintains a pool of receive buffers and continuously keeps receives queued
type ioUringRecvState struct {
	fd      int
	sqRing  []byte
	cqRing  []byte
	sqesMap []byte
	sqes    []ioUringSqe
	cqCqes  []ioUringCqe

	sqHead        *uint32
	sqTail        *uint32
	sqRingMask    *uint32
	sqRingEntries *uint32
	sqArray       []uint32

	cqHead        *uint32
	cqTail        *uint32
	cqRingMask    *uint32
	cqRingEntries *uint32

	mu         sync.Mutex
	userData   uint64
	bufferPool []*recvBuffer          // Pool of all receive buffers
	bufferMap  map[uint64]*recvBuffer // Map userData -> buffer

	sqEntryCount uint32
	cqEntryCount uint32

	sockFd int // Socket file descriptor to receive from
	closed atomic.Bool
}

func alignUint32(v, alignment uint32) uint32 {
	if alignment == 0 {
		return v
	}
	mod := v % alignment
	if mod == 0 {
		return v
	}
	return v + alignment - mod
}

func newIoUringState(entries uint32) (*ioUringState, error) {
	const minEntries = 8

	if entries == 0 {
		entries = defaultIoUringEntries
	}
	if entries < minEntries {
		entries = minEntries
	}

	tries := entries
	var params ioUringParams

	// Try flag combinations in order (5.19+ -> baseline)
	// Note: SINGLE_ISSUER causes EEXIST errors, so it's excluded
	flagSets := []uint32{
		ioringSetupClamp | ioringSetupCoopTaskrun, // Kernel 5.19+: reduce thread creation
		ioringSetupClamp, // All kernels
	}
	flagSetIdx := 0

	for {
		params = ioUringParams{Flags: flagSets[flagSetIdx]}
		fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, uintptr(tries), uintptr(unsafe.Pointer(&params)), 0)
		if errno != 0 {
			// If EINVAL, try next flag set (kernel doesn't support these flags)
			if errno == unix.EINVAL && flagSetIdx < len(flagSets)-1 {
				flagSetIdx++
				continue
			}
			if errno == unix.ENOMEM && tries > minEntries {
				tries /= 2
				if tries < minEntries {
					tries = minEntries
				}
				continue
			}
			return nil, errno
		}

		ring := &ioUringState{
			fd:              int(fd),
			sqEntryCount:    params.SqEntries,
			cqEntryCount:    params.CqEntries,
			userData:        1,
			pendingSends:    make(map[uint64]*pendingSend),
			pendingReceives: make(map[uint64]*pendingRecv),
			completedCqes:   make(map[uint64]*ioUringCqe),
		}

		if err := ring.mapRings(&params); err != nil {
			ring.Close()
			if errors.Is(err, unix.ENOMEM) && tries > minEntries {
				tries /= 2
				if tries < minEntries {
					tries = minEntries
				}
				continue
			}
			return nil, err
		}

		// Limit kernel worker threads to prevent thousands being spawned
		// [0] = bounded workers, [1] = unbounded workers
		maxWorkers := [2]uint32{4, 4} // Limit to 4 workers of each type
		_, _, errno = unix.Syscall6(
			unix.SYS_IO_URING_REGISTER,
			uintptr(fd),
			uintptr(ioringRegisterIowqMaxWorkers),
			uintptr(unsafe.Pointer(&maxWorkers[0])),
			2, // array length
			0, 0,
		)
		// Ignore errors - older kernels don't support this

		return ring, nil
	}
}

func (r *ioUringState) mapRings(params *ioUringParams) error {
	pageSize := uint32(unix.Getpagesize())

	sqRingSize := alignUint32(params.SqOff.Array+params.SqEntries*4, pageSize)
	cqRingSize := alignUint32(params.CqOff.Cqes+params.CqEntries*uint32(unsafe.Sizeof(ioUringCqe{})), pageSize)
	sqesSize := alignUint32(params.SqEntries*ioUringSqeSize, pageSize)

	sqRing, err := unix.Mmap(r.fd, ioringOffSqRing, int(sqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	r.sqRing = sqRing

	cqRing, err := unix.Mmap(r.fd, ioringOffCqRing, int(cqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(r.sqRing)
		r.sqRing = nil
		return err
	}
	r.cqRing = cqRing

	sqesMap, err := unix.Mmap(r.fd, ioringOffSqes, int(sqesSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(r.cqRing)
		unix.Munmap(r.sqRing)
		r.cqRing = nil
		r.sqRing = nil
		return err
	}
	r.sqesMap = sqesMap

	sqBase := unsafe.Pointer(&sqRing[0])
	r.sqHead = (*uint32)(unsafe.Pointer(uintptr(sqBase) + uintptr(params.SqOff.Head)))
	r.sqTail = (*uint32)(unsafe.Pointer(uintptr(sqBase) + uintptr(params.SqOff.Tail)))
	r.sqRingMask = (*uint32)(unsafe.Pointer(uintptr(sqBase) + uintptr(params.SqOff.RingMask)))
	r.sqRingEntries = (*uint32)(unsafe.Pointer(uintptr(sqBase) + uintptr(params.SqOff.RingEntries)))
	arrayPtr := unsafe.Pointer(uintptr(sqBase) + uintptr(params.SqOff.Array))
	r.sqArray = unsafe.Slice((*uint32)(arrayPtr), int(params.SqEntries))

	sqesBase := unsafe.Pointer(&sqesMap[0])
	r.sqes = unsafe.Slice((*ioUringSqe)(sqesBase), int(params.SqEntries))

	cqBase := unsafe.Pointer(&cqRing[0])
	r.cqHead = (*uint32)(unsafe.Pointer(uintptr(cqBase) + uintptr(params.CqOff.Head)))
	r.cqTail = (*uint32)(unsafe.Pointer(uintptr(cqBase) + uintptr(params.CqOff.Tail)))
	r.cqRingMask = (*uint32)(unsafe.Pointer(uintptr(cqBase) + uintptr(params.CqOff.RingMask)))
	r.cqRingEntries = (*uint32)(unsafe.Pointer(uintptr(cqBase) + uintptr(params.CqOff.RingEntries)))
	cqesPtr := unsafe.Pointer(uintptr(cqBase) + uintptr(params.CqOff.Cqes))

	// CRITICAL: Ensure CQE array pointer is properly aligned
	// The kernel's CQE structure is 16 bytes, and the array must be aligned
	// Verify alignment and log if misaligned
	cqeSize := uintptr(unsafe.Sizeof(ioUringCqe{}))
	if cqeSize != 16 {
		return fmt.Errorf("io_uring CQE size mismatch: expected 16, got %d", cqeSize)
	}
	cqesOffset := uintptr(cqesPtr) % 8
	if cqesOffset != 0 {
		logrus.WithFields(logrus.Fields{
			"cqes_ptr":    fmt.Sprintf("%p", cqesPtr),
			"cqes_offset": cqesOffset,
			"cq_base":     fmt.Sprintf("%p", cqBase),
			"cq_off_cqes": params.CqOff.Cqes,
		}).Warn("io_uring CQE array may be misaligned")
	}

	r.cqCqes = unsafe.Slice((*ioUringCqe)(cqesPtr), int(params.CqEntries))

	return nil
}

func (r *ioUringState) getSqeLocked() (*ioUringSqe, error) {
	iterations := 0
	for {
		head := atomic.LoadUint32(r.sqHead)
		tail := atomic.LoadUint32(r.sqTail)
		entries := atomic.LoadUint32(r.sqRingEntries)
		used := tail - head

		if tail-head < entries {
			mask := atomic.LoadUint32(r.sqRingMask)
			idx := tail & mask
			sqe := &r.sqes[idx]
			*sqe = ioUringSqe{}
			r.sqArray[idx] = idx
			atomic.StoreUint32(r.sqTail, tail+1)
			if iterations > 0 {
				logrus.WithFields(logrus.Fields{
					"iterations": iterations,
					"used":       used,
					"entries":    entries,
				}).Debug("getSqeLocked got slot after waiting")
			}
			return sqe, nil
		}

		logrus.WithFields(logrus.Fields{
			"head":    head,
			"tail":    tail,
			"entries": entries,
			"used":    used,
		}).Warn("getSqeLocked: io_uring ring is FULL, waiting for completions")

		if err := r.submitAndWaitLocked(0, 1); err != nil {
			return nil, err
		}
		iterations++
	}
}

func (r *ioUringState) submitAndWaitLocked(submit, wait uint32) error {
	var flags uintptr
	if wait > 0 {
		flags = ioringEnterGetevents
	}

	for {
		_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(r.fd), uintptr(submit), uintptr(wait), flags, 0, 0)
		if errno == 0 {
			return nil
		}
		if errno == unix.EINTR {
			continue
		}
		return errno
	}
}

func (r *ioUringState) enqueueSendmsgLocked(fd int, msg *unix.Msghdr, msgFlags uint32, payloadLen uint32) (uint64, error) {
	sqe, err := r.getSqeLocked()
	if err != nil {
		return 0, err
	}

	userData := r.userData
	r.userData++

	msgCopy := new(unix.Msghdr)
	*msgCopy = *msg

	var iovCopy *unix.Iovec
	var payloadRef unsafe.Pointer
	if msg.Iov != nil {
		iovCopy = new(unix.Iovec)
		*iovCopy = *msg.Iov
		msgCopy.Iov = iovCopy
		if iovCopy.Base != nil {
			payloadRef = unsafe.Pointer(iovCopy.Base)
		}
	}

	var sockaddrCopy []byte
	if msg.Name != nil && msg.Namelen > 0 {
		sockaddrCopy = make([]byte, msg.Namelen)
		copy(sockaddrCopy, (*[256]byte)(unsafe.Pointer(msg.Name))[:msg.Namelen])
		msgCopy.Name = &sockaddrCopy[0]
	}

	var controlCopy []byte
	if msg.Control != nil && msg.Controllen > 0 {
		controlCopy = make([]byte, msg.Controllen)
		copy(controlCopy, (*[256]byte)(unsafe.Pointer(msg.Control))[:msg.Controllen])
		msgCopy.Control = &controlCopy[0]
	}

	pending := &pendingSend{
		msgCopy:      msgCopy,
		iovCopy:      iovCopy,
		sockaddrCopy: sockaddrCopy,
		controlCopy:  controlCopy,
		payloadRef:   payloadRef,
		userData:     userData,
	}
	r.pendingSends[userData] = pending

	sqe.Opcode = ioringOpSendmsg
	sqe.Fd = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(msgCopy)))
	sqe.Len = 0
	sqe.MsgFlags = msgFlags
	sqe.Flags = 0

	userDataPtr := (*uint64)(unsafe.Pointer(&sqe.UserData))
	atomic.StoreUint64(userDataPtr, userData)
	_ = atomic.LoadUint64(userDataPtr)

	runtime.KeepAlive(msgCopy)
	runtime.KeepAlive(sqe)
	if payloadRef != nil {
		runtime.KeepAlive(payloadRef)
	}
	_ = atomic.LoadUint32(r.sqTail)
	atomic.StoreUint32(r.sqTail, atomic.LoadUint32(r.sqTail))

	return userData, nil
}

func (r *ioUringState) abortPendingSendLocked(userData uint64) {
	if pending, ok := r.pendingSends[userData]; ok {
		delete(r.pendingSends, userData)
		delete(r.completedCqes, userData)
		if pending != nil {
			runtime.KeepAlive(pending.msgCopy)
			runtime.KeepAlive(pending.iovCopy)
			runtime.KeepAlive(pending.sockaddrCopy)
			runtime.KeepAlive(pending.controlCopy)
			if pending.payloadRef != nil {
				runtime.KeepAlive(pending.payloadRef)
			}
		}
	}
}

func (r *ioUringState) abortPendingRecvLocked(userData uint64) {
	if pending, ok := r.pendingReceives[userData]; ok {
		delete(r.pendingReceives, userData)
		delete(r.completedCqes, userData)
		if pending != nil {
			runtime.KeepAlive(pending.msgCopy)
			runtime.KeepAlive(pending.iovCopy)
			runtime.KeepAlive(pending.payloadBuf)
			runtime.KeepAlive(pending.nameBuf)
			runtime.KeepAlive(pending.controlBuf)
		}
	}
}

func (r *ioUringState) completeSendLocked(userData uint64) (int32, uint32, error) {
	cqe, err := r.waitForCqeLocked(userData)
	if err != nil {
		r.abortPendingSendLocked(userData)
		return 0, 0, err
	}

	var pending *pendingSend
	if p, ok := r.pendingSends[userData]; ok {
		pending = p
		delete(r.pendingSends, userData)
	}

	if pending != nil {
		runtime.KeepAlive(pending.msgCopy)
		runtime.KeepAlive(pending.iovCopy)
		runtime.KeepAlive(pending.sockaddrCopy)
		runtime.KeepAlive(pending.controlCopy)
		if pending.payloadRef != nil {
			runtime.KeepAlive(pending.payloadRef)
		}
	}

	return cqe.Res, cqe.Flags, nil
}

func (r *ioUringState) enqueueRecvmsgLocked(fd int, msg *unix.Msghdr, msgFlags uint32) (uint64, error) {
	if msg == nil {
		return 0, syscall.EINVAL
	}

	var iovCount int
	if msg.Iov != nil {
		iovCount = int(msg.Iovlen)
		if iovCount <= 0 {
			return 0, syscall.EINVAL
		}
		if iovCount > 1 {
			return 0, syscall.ENOTSUP
		}
	}

	sqe, err := r.getSqeLocked()
	if err != nil {
		return 0, err
	}

	userData := r.userData
	r.userData++

	msgCopy := new(unix.Msghdr)
	*msgCopy = *msg

	var iovCopy *unix.Iovec
	var payloadBuf []byte
	if msg.Iov != nil {
		iovCopy = new(unix.Iovec)
		*iovCopy = *msg.Iov
		msgCopy.Iov = iovCopy
		setMsghdrIovlen(msgCopy, 1)
		if iovCopy.Base != nil {
			payloadLen := int(iovCopy.Len)
			if payloadLen < 0 {
				return 0, syscall.EINVAL
			}
			if payloadLen > 0 {
				payloadBuf = unsafe.Slice((*byte)(iovCopy.Base), payloadLen)
			}
		}
	}

	var nameBuf []byte
	if msgCopy.Name != nil && msgCopy.Namelen > 0 {
		nameLen := int(msgCopy.Namelen)
		if nameLen < 0 {
			return 0, syscall.EINVAL
		}
		nameBuf = unsafe.Slice(msgCopy.Name, nameLen)
	}

	var controlBuf []byte
	if msgCopy.Control != nil && msgCopy.Controllen > 0 {
		ctrlLen := int(msgCopy.Controllen)
		if ctrlLen < 0 {
			return 0, syscall.EINVAL
		}
		if ctrlLen > 0 {
			controlBuf = unsafe.Slice((*byte)(msgCopy.Control), ctrlLen)
		}
	}

	pending := &pendingRecv{
		msgCopy:    msgCopy,
		iovCopy:    iovCopy,
		nameBuf:    nameBuf,
		controlBuf: controlBuf,
		payloadBuf: payloadBuf,
		callerMsg:  msg,
		userData:   userData,
	}
	r.pendingReceives[userData] = pending

	sqe.Opcode = ioringOpRecvmsg
	sqe.Fd = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(msgCopy)))
	sqe.Len = 0
	sqe.MsgFlags = msgFlags
	sqe.Flags = 0

	userDataPtr := (*uint64)(unsafe.Pointer(&sqe.UserData))
	atomic.StoreUint64(userDataPtr, userData)
	_ = atomic.LoadUint64(userDataPtr)

	runtime.KeepAlive(msgCopy)
	runtime.KeepAlive(iovCopy)
	runtime.KeepAlive(payloadBuf)
	runtime.KeepAlive(nameBuf)
	runtime.KeepAlive(controlBuf)

	return userData, nil
}

func (r *ioUringState) completeRecvLocked(userData uint64) (int32, uint32, error) {
	cqe, err := r.waitForCqeLocked(userData)
	if err != nil {
		r.abortPendingRecvLocked(userData)
		return 0, 0, err
	}

	var pending *pendingRecv
	if p, ok := r.pendingReceives[userData]; ok {
		pending = p
		delete(r.pendingReceives, userData)
	}

	if pending != nil {
		if pending.callerMsg != nil && pending.msgCopy != nil {
			pending.callerMsg.Namelen = pending.msgCopy.Namelen
			pending.callerMsg.Controllen = pending.msgCopy.Controllen
			pending.callerMsg.Flags = pending.msgCopy.Flags
		}
		runtime.KeepAlive(pending.msgCopy)
		runtime.KeepAlive(pending.iovCopy)
		runtime.KeepAlive(pending.payloadBuf)
		runtime.KeepAlive(pending.nameBuf)
		runtime.KeepAlive(pending.controlBuf)
	}

	return cqe.Res, cqe.Flags, nil
}

func (r *ioUringState) SendmsgBatch(entries []ioUringBatchEntry) error {
	if len(entries) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	startTail := atomic.LoadUint32(r.sqTail)
	prepared := 0
	for i := range entries {
		entry := &entries[i]
		userData, err := r.enqueueSendmsgLocked(entry.fd, entry.msg, entry.msgFlags, entry.payloadLen)
		if err != nil {
			for j := 0; j < prepared; j++ {
				r.abortPendingSendLocked(entries[j].userData)
			}
			return err
		}
		entry.userData = userData
		prepared++
	}

	submit := atomic.LoadUint32(r.sqTail) - startTail
	if submit == 0 {
		return nil
	}

	if err := r.submitAndWaitLocked(submit, submit); err != nil {
		for i := 0; i < prepared; i++ {
			r.abortPendingSendLocked(entries[i].userData)
		}
		return err
	}

	for i := range entries {
		entry := &entries[i]
		res, flags, err := r.completeSendLocked(entry.userData)
		if entry.result != nil {
			entry.result.res = res
			entry.result.flags = flags
			entry.result.err = err
		}
	}

	return nil
}

func (r *ioUringState) popCqeLocked() (*ioUringCqe, error) {
	for {
		// According to io_uring ABI specification:
		// 1. Load tail with acquire semantics (ensures we see kernel's update)
		// 2. Load head (our consumer index)
		// 3. If head != tail, CQE available at index (head & mask)
		// 4. Read CQE (must happen before updating head)
		// 5. Update head with release semantics (marks CQE as consumed)

		// CRITICAL: According to io_uring ABI, the correct order is:
		// 1. Load tail with acquire semantics (ensures we see kernel's tail update)
		// 2. Load head (our consumer index)
		// 3. If head != tail, read CQE at index (head & mask)
		// 4. Update head with release semantics (marks CQE as consumed)
		// The acquire/release pair ensures we see the kernel's CQE writes

		// Load tail with acquire semantics - this ensures we see all kernel writes
		// including the CQE data
		tail := atomic.LoadUint32(r.cqTail)

		// Load head (our consumer index)
		head := atomic.LoadUint32(r.cqHead)

		if head != tail {
			// CQE available - calculate index using mask
			mask := atomic.LoadUint32(r.cqRingMask)
			idx := head & mask

			// Get pointer to CQE entry - this points into mmapped kernel memory
			cqe := &r.cqCqes[idx]

			// CRITICAL: The kernel writes the CQE with release semantics when it
			// updates tail. Since we loaded tail with acquire semantics above,
			// we should see the CQE correctly. However, we need to ensure we're
			// reading the fields in the correct order and with proper barriers.

			// Read UserData field - use atomic load to ensure proper ordering
			// The kernel's write to user_data happens before updating tail (release)
			userDataPtr := (*uint64)(unsafe.Pointer(&cqe.UserData))
			userData := atomic.LoadUint64(userDataPtr)

			// Memory barrier: ensure UserData read completes before reading other fields
			// This creates a proper acquire barrier
			_ = atomic.LoadUint32(r.cqTail)

			// Read other fields - these should be visible after the barrier
			res := cqe.Res
			flags := cqe.Flags

			// NOW update head with release semantics
			// This marks the CQE as consumed and must happen AFTER all reads
			atomic.StoreUint32(r.cqHead, head+1)

			// Return a copy to ensure consistency - the original CQE in mmapped
			// memory might be overwritten by the kernel for the next submission
			return &ioUringCqe{
				UserData: userData,
				Res:      res,
				Flags:    flags,
			}, nil
		}

		// No CQE available - wait for kernel to add one
		if err := r.submitAndWaitLocked(0, 1); err != nil {
			return nil, err
		}
	}
}

// waitForCqeLocked waits for a CQE matching the expected userData.
// It drains any CQEs that don't match (from previous submissions that completed
// out of order) until it finds the one we're waiting for.
func (r *ioUringState) waitForCqeLocked(expectedUserData uint64) (*ioUringCqe, error) {
	if cqe, ok := r.completedCqes[expectedUserData]; ok {
		delete(r.completedCqes, expectedUserData)
		return cqe, nil
	}

	const maxIterations = 1000
	for iterations := 0; ; iterations++ {
		if iterations >= maxIterations {
			logrus.WithFields(logrus.Fields{
				"expected_userdata": expectedUserData,
				"pending_sends":     len(r.pendingSends),
				"pending_recvs":     len(r.pendingReceives),
				"completed_cache":   len(r.completedCqes),
			}).Error("io_uring waitForCqeLocked exceeded max iterations - possible bug")
			return nil, syscall.EIO
		}

		cqe, err := r.popCqeLocked()
		if err != nil {
			return nil, err
		}
		userData := cqe.UserData

		logrus.WithFields(logrus.Fields{
			"cqe_userdata":      userData,
			"cqe_userdata_hex":  fmt.Sprintf("0x%x", userData),
			"cqe_res":           cqe.Res,
			"cqe_flags":         cqe.Flags,
			"expected_userdata": expectedUserData,
		}).Debug("io_uring CQE received")

		if userData == expectedUserData {
			return cqe, nil
		}

		if _, exists := r.completedCqes[userData]; exists {
			logrus.WithFields(logrus.Fields{
				"cqe_userdata": userData,
			}).Warn("io_uring received duplicate CQE for userData; overwriting previous entry")
		}

		r.completedCqes[userData] = cqe

		if _, sendPending := r.pendingSends[userData]; !sendPending {
			if _, recvPending := r.pendingReceives[userData]; !recvPending {
				logrus.WithFields(logrus.Fields{
					"cqe_userdata": userData,
					"cqe_res":      cqe.Res,
					"cqe_flags":    cqe.Flags,
				}).Warn("io_uring received CQE for unknown userData; stored for later but no pending op found")
			}
		}
	}
}

func (r *ioUringState) Sendmsg(fd int, msg *unix.Msghdr, msgFlags uint32, payloadLen uint32) (int, error) {
	if r == nil {
		return 0, &net.OpError{Op: "sendmsg", Err: syscall.EINVAL}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	userData, err := r.enqueueSendmsgLocked(fd, msg, msgFlags, payloadLen)
	if err != nil {
		return 0, &net.OpError{Op: "sendmsg", Err: err}
	}

	if err := r.submitAndWaitLocked(1, 1); err != nil {
		r.abortPendingSendLocked(userData)
		return 0, &net.OpError{Op: "sendmsg", Err: err}
	}

	res, cqeFlags, err := r.completeSendLocked(userData)
	if err != nil {
		return 0, &net.OpError{Op: "sendmsg", Err: err}
	}

	if res < 0 {
		errno := syscall.Errno(-res)
		return 0, &net.OpError{Op: "sendmsg", Err: errno}
	}
	if res == 0 && payloadLen > 0 {
		logrus.WithFields(logrus.Fields{
			"payload_len":  payloadLen,
			"msg_namelen":  msg.Namelen,
			"msg_flags":    msgFlags,
			"cqe_flags":    cqeFlags,
			"cqe_userdata": userData,
		}).Warn("io_uring sendmsg returned zero bytes")
	}

	return int(res), nil
}

func (r *ioUringState) Recvmsg(fd int, msg *unix.Msghdr, msgFlags uint32) (int, uint32, error) {

	if r == nil {
		logrus.Error("io_uring Recvmsg: r is nil")
		return 0, 0, &net.OpError{Op: "recvmsg", Err: syscall.EINVAL}
	}

	if msg == nil {
		logrus.Error("io_uring Recvmsg: msg is nil")
		return 0, 0, &net.OpError{Op: "recvmsg", Err: syscall.EINVAL}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	userData, err := r.enqueueRecvmsgLocked(fd, msg, msgFlags)
	if err != nil {
		return 0, 0, &net.OpError{Op: "recvmsg", Err: err}
	}

	if err := r.submitAndWaitLocked(1, 1); err != nil {
		r.abortPendingRecvLocked(userData)
		return 0, 0, &net.OpError{Op: "recvmsg", Err: err}
	}

	res, cqeFlags, err := r.completeRecvLocked(userData)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"userData": userData,
			"error":    err,
		}).Error("io_uring completeRecvLocked failed")
		return 0, 0, &net.OpError{Op: "recvmsg", Err: err}
	}

	logrus.WithFields(logrus.Fields{
		"userData":  userData,
		"res":       res,
		"cqeFlags":  cqeFlags,
		"bytesRecv": res,
	}).Debug("io_uring recvmsg completed")

	if res < 0 {
		errno := syscall.Errno(-res)
		logrus.WithFields(logrus.Fields{
			"userData": userData,
			"res":      res,
			"errno":    errno,
		}).Error("io_uring recvmsg negative result")
		return 0, cqeFlags, &net.OpError{Op: "recvmsg", Err: errno}
	}

	return int(res), cqeFlags, nil
}

func (r *ioUringState) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	// Clean up any remaining pending sends
	for _, pending := range r.pendingSends {
		runtime.KeepAlive(pending)
	}
	r.pendingSends = nil
	for _, pending := range r.pendingReceives {
		runtime.KeepAlive(pending)
	}
	r.pendingReceives = nil
	r.completedCqes = nil
	r.mu.Unlock()

	var err error
	if r.sqRing != nil {
		if e := unix.Munmap(r.sqRing); e != nil && err == nil {
			err = e
		}
		r.sqRing = nil
	}
	if r.cqRing != nil {
		if e := unix.Munmap(r.cqRing); e != nil && err == nil {
			err = e
		}
		r.cqRing = nil
	}
	if r.sqesMap != nil {
		if e := unix.Munmap(r.sqesMap); e != nil && err == nil {
			err = e
		}
		r.sqesMap = nil
	}
	if r.fd >= 0 {
		if e := unix.Close(r.fd); e != nil && err == nil {
			err = e
		}
		r.fd = -1
	}
	return err
}

// RecvPacket represents a received packet with its metadata
type RecvPacket struct {
	Data        []byte
	N           int
	From        *unix.RawSockaddrInet6
	Flags       uint32
	Control     []byte
	Controllen  int
	RecycleFunc func()
}

var recvPacketDataPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536) // Max UDP packet size
		return &b
	},
}

var recvControlDataPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 256) // Max control message size
		return &b
	},
}

// newIoUringRecvState creates a dedicated io_uring for receiving packets
// poolSize determines how many receive operations to keep queued
func newIoUringRecvState(sockFd int, entries uint32, poolSize int, bufferSize int) (*ioUringRecvState, error) {
	const minEntries = 8

	if poolSize < 1 {
		poolSize = 64 // Default pool size
	}
	if poolSize > 2048 {
		poolSize = 2048 // Cap pool size
	}

	if entries == 0 {
		entries = uint32(poolSize)
	}
	if entries < uint32(poolSize) {
		entries = uint32(poolSize)
	}
	if entries < minEntries {
		entries = minEntries
	}

	tries := entries
	var params ioUringParams

	// Try flag combinations in order (5.19+ -> baseline)
	// Note: SINGLE_ISSUER causes EEXIST errors, so it's excluded
	flagSets := []uint32{
		ioringSetupClamp | ioringSetupCoopTaskrun, // Kernel 5.19+: reduce thread creation
		ioringSetupClamp, // All kernels
	}
	flagSetIdx := 0

	for {
		params = ioUringParams{Flags: flagSets[flagSetIdx]}
		fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, uintptr(tries), uintptr(unsafe.Pointer(&params)), 0)
		if errno != 0 {
			// If EINVAL, try next flag set (kernel doesn't support these flags)
			if errno == unix.EINVAL && flagSetIdx < len(flagSets)-1 {
				flagSetIdx++
				continue
			}
			if errno == unix.ENOMEM && tries > minEntries {
				tries /= 2
				if tries < minEntries {
					tries = minEntries
				}
				continue
			}
			return nil, errno
		}

		ring := &ioUringRecvState{
			fd:           int(fd),
			sqEntryCount: params.SqEntries,
			cqEntryCount: params.CqEntries,
			userData:     1,
			bufferMap:    make(map[uint64]*recvBuffer),
			sockFd:       sockFd,
		}

		if err := ring.mapRings(&params); err != nil {
			ring.Close()
			if errors.Is(err, unix.ENOMEM) && tries > minEntries {
				tries /= 2
				if tries < minEntries {
					tries = minEntries
				}
				continue
			}
			return nil, err
		}

		// Allocate buffer pool
		ring.bufferPool = make([]*recvBuffer, poolSize)
		for i := 0; i < poolSize; i++ {
			buf := &recvBuffer{
				payloadBuf: make([]byte, bufferSize),
				nameBuf:    make([]byte, unix.SizeofSockaddrInet6),
				controlBuf: make([]byte, 256),
				msghdr:     &unix.Msghdr{},
				iovec:      &unix.Iovec{},
				userData:   ring.userData,
			}
			ring.userData++

			// Initialize iovec to point to payload buffer
			buf.iovec.Base = &buf.payloadBuf[0]
			buf.iovec.SetLen(len(buf.payloadBuf))

			// Initialize msghdr
			buf.msghdr.Name = &buf.nameBuf[0]
			buf.msghdr.Namelen = uint32(len(buf.nameBuf))
			buf.msghdr.Iov = buf.iovec
			buf.msghdr.Iovlen = 1
			buf.msghdr.Control = &buf.controlBuf[0]
			buf.msghdr.Controllen = controllen(len(buf.controlBuf))

			ring.bufferPool[i] = buf
			ring.bufferMap[buf.userData] = buf
		}

		logrus.WithFields(logrus.Fields{
			"poolSize":   poolSize,
			"entries":    ring.sqEntryCount,
			"bufferSize": bufferSize,
		}).Info("io_uring receive ring created")

		// Limit kernel worker threads to prevent thousands being spawned
		// [0] = bounded workers, [1] = unbounded workers
		maxWorkers := [2]uint32{4, 4} // Limit to 4 workers of each type
		_, _, errno = unix.Syscall6(
			unix.SYS_IO_URING_REGISTER,
			uintptr(fd),
			uintptr(ioringRegisterIowqMaxWorkers),
			uintptr(unsafe.Pointer(&maxWorkers[0])),
			2, // array length
			0, 0,
		)
		// Ignore errors - older kernels don't support this

		return ring, nil
	}
}

func (r *ioUringRecvState) mapRings(params *ioUringParams) error {
	pageSize := uint32(unix.Getpagesize())

	sqRingSize := alignUint32(params.SqOff.Array+params.SqEntries*4, pageSize)
	cqRingSize := alignUint32(params.CqOff.Cqes+params.CqEntries*16, pageSize)

	if params.Features&(1<<0) != 0 { // IORING_FEAT_SINGLE_MMAP
		if sqRingSize > cqRingSize {
			cqRingSize = sqRingSize
		} else {
			sqRingSize = cqRingSize
		}
	}

	sqRingPtr, err := unix.Mmap(r.fd, int64(ioringOffSqRing), int(sqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return err
	}
	r.sqRing = sqRingPtr

	if params.Features&(1<<0) != 0 {
		r.cqRing = sqRingPtr
	} else {
		cqRingPtr, err := unix.Mmap(r.fd, int64(ioringOffCqRing), int(cqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return err
		}
		r.cqRing = cqRingPtr
	}

	sqesSize := int(params.SqEntries) * ioUringSqeSize
	sqesPtr, err := unix.Mmap(r.fd, int64(ioringOffSqes), sqesSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return err
	}
	r.sqesMap = sqesPtr

	// Set up SQ pointers
	r.sqHead = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.Head]))
	r.sqTail = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.Tail]))
	r.sqRingMask = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.RingMask]))
	r.sqRingEntries = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.RingEntries]))

	// Set up SQ array
	arrayBase := unsafe.Pointer(&r.sqRing[params.SqOff.Array])
	r.sqArray = unsafe.Slice((*uint32)(arrayBase), params.SqEntries)

	// Set up SQE slice
	r.sqes = unsafe.Slice((*ioUringSqe)(unsafe.Pointer(&sqesPtr[0])), params.SqEntries)

	// Set up CQ pointers
	r.cqHead = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.Head]))
	r.cqTail = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.Tail]))
	r.cqRingMask = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.RingMask]))
	r.cqRingEntries = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.RingEntries]))

	cqesBase := unsafe.Pointer(&r.cqRing[params.CqOff.Cqes])
	r.cqCqes = unsafe.Slice((*ioUringCqe)(cqesBase), params.CqEntries)

	return nil
}

// submitRecvLocked submits a single receive operation. Must be called with mutex held.
func (r *ioUringRecvState) submitRecvLocked(buf *recvBuffer) error {
	if buf.inFlight.Load() {
		return fmt.Errorf("buffer already in flight")
	}

	// Reset buffer state for reuse
	buf.msghdr.Namelen = uint32(len(buf.nameBuf))
	buf.msghdr.Controllen = controllen(len(buf.controlBuf))
	buf.msghdr.Flags = 0
	buf.iovec.SetLen(len(buf.payloadBuf))

	// Get next SQE
	tail := atomic.LoadUint32(r.sqTail)
	head := atomic.LoadUint32(r.sqHead)
	mask := *r.sqRingMask

	if tail-head >= *r.sqRingEntries {
		return fmt.Errorf("submission queue full")
	}

	idx := tail & mask
	sqe := &r.sqes[idx]

	// Set up SQE for IORING_OP_RECVMSG
	*sqe = ioUringSqe{}
	sqe.Opcode = ioringOpRecvmsg
	sqe.Fd = int32(r.sockFd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(buf.msghdr)))
	sqe.Len = 1
	sqe.UserData = buf.userData

	r.sqArray[idx] = uint32(idx)
	atomic.StoreUint32(r.sqTail, tail+1)

	buf.inFlight.Store(true)

	return nil
}

// submitAndWaitLocked submits pending SQEs and optionally waits for completions
func (r *ioUringRecvState) submitAndWaitLocked(submit, wait uint32) error {
	var flags uintptr
	if wait > 0 {
		flags = ioringEnterGetevents
	}

	for {
		ret, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(r.fd), uintptr(submit), uintptr(wait), flags, 0, 0)
		if errno == 0 {
			if wait > 0 && ret > 0 {
				logrus.WithFields(logrus.Fields{
					"completed": ret,
					"submitted": submit,
				}).Debug("io_uring recv: operations completed")
			}
			return nil
		}
		if errno == unix.EINTR {
			continue
		}
		return errno
	}
}

// fillRecvQueue fills the submission queue with as many receives as possible
func (r *ioUringRecvState) fillRecvQueue() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return fmt.Errorf("ring closed")
	}

	submitted := uint32(0)
	for _, buf := range r.bufferPool {
		if !buf.inFlight.Load() {
			if err := r.submitRecvLocked(buf); err != nil {
				if submitted > 0 {
					break // Queue full, submit what we have
				}
				return err
			}
			submitted++
		}
	}

	if submitted > 0 {
		return r.submitAndWaitLocked(submitted, 0)
	}

	return nil
}

// receivePackets processes all completed receives and returns packets
// Returns a slice of completed packets
func (r *ioUringRecvState) receivePackets(wait bool) ([]RecvPacket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return nil, fmt.Errorf("ring closed")
	}

	// First submit any pending (to ensure we always have receives queued)
	submitted := uint32(0)
	for _, buf := range r.bufferPool {
		if !buf.inFlight.Load() {
			if err := r.submitRecvLocked(buf); err != nil {
				break // Queue might be full
			}
			submitted++
		}
	}

	waitCount := uint32(0)
	if wait {
		waitCount = 1
	}

	if submitted > 0 || wait {
		if err := r.submitAndWaitLocked(submitted, waitCount); err != nil {
			return nil, err
		}
	}

	// Process completed CQEs
	var packets []RecvPacket
	head := atomic.LoadUint32(r.cqHead)
	tail := atomic.LoadUint32(r.cqTail)
	mask := *r.cqRingMask

	completions := uint32(0)
	errors := 0
	eagains := 0

	for head != tail {
		idx := head & mask
		cqe := &r.cqCqes[idx]

		userData := cqe.UserData
		res := cqe.Res
		flags := cqe.Flags

		head++
		atomic.StoreUint32(r.cqHead, head)
		completions++

		buf, ok := r.bufferMap[userData]
		if !ok {
			logrus.WithField("userData", userData).Warn("io_uring recv: unknown userData in completion")
			continue
		}

		buf.inFlight.Store(false)

		if res < 0 {
			errno := syscall.Errno(-res)
			// EAGAIN is expected for non-blocking - just resubmit
			if errno == unix.EAGAIN {
				eagains++
			} else {
				errors++
				logrus.WithFields(logrus.Fields{
					"userData": userData,
					"errno":    errno,
				}).Debug("io_uring recv error")
			}
			continue
		}

		if res == 0 {
			// Connection closed or no data
			continue
		}

		// Successfully received packet
		n := int(res)

		// Copy address
		var from unix.RawSockaddrInet6
		if buf.msghdr.Namelen > 0 && buf.msghdr.Namelen <= uint32(len(buf.nameBuf)) {
			copy((*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&from)))[:], buf.nameBuf[:buf.msghdr.Namelen])
		}

		// Get buffer from pool and copy data
		dataBufPtr := recvPacketDataPool.Get().(*[]byte)
		dataBuf := *dataBufPtr
		if cap(dataBuf) < n {
			// Buffer too small, allocate new one
			dataBuf = make([]byte, n)
		} else {
			dataBuf = dataBuf[:n]
		}
		copy(dataBuf, buf.payloadBuf[:n])

		// Copy control messages if present
		var controlBuf []byte
		var controlBufPtr *[]byte
		controllen := int(buf.msghdr.Controllen)
		if controllen > 0 && controllen <= len(buf.controlBuf) {
			controlBufPtr = recvControlDataPool.Get().(*[]byte)
			controlBuf = (*controlBufPtr)[:controllen]
			copy(controlBuf, buf.controlBuf[:controllen])
		}

		packets = append(packets, RecvPacket{
			Data:       dataBuf,
			N:          n,
			From:       &from,
			Flags:      flags,
			Control:    controlBuf,
			Controllen: controllen,
			RecycleFunc: func() {
				// Return buffers to pool
				recvPacketDataPool.Put(dataBufPtr)
				if controlBufPtr != nil {
					recvControlDataPool.Put(controlBufPtr)
				}
			},
		})
	}

	return packets, nil
}

// Close shuts down the receive ring
func (r *ioUringRecvState) Close() error {
	if r == nil {
		return nil
	}

	r.closed.Store(true)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clean up buffers
	for _, buf := range r.bufferPool {
		buf.inFlight.Store(false)
	}
	r.bufferPool = nil
	r.bufferMap = nil

	var err error
	if r.sqesMap != nil {
		if e := unix.Munmap(r.sqesMap); e != nil && err == nil {
			err = e
		}
		r.sqesMap = nil
	}
	if r.sqRing != nil {
		if e := unix.Munmap(r.sqRing); e != nil && err == nil {
			err = e
		}
		r.sqRing = nil
	}
	if r.cqRing != nil && len(r.cqRing) > 0 {
		// Only unmap if it's a separate mapping
		if len(r.cqRing) != len(r.sqRing) || uintptr(unsafe.Pointer(&r.cqRing[0])) != uintptr(unsafe.Pointer(&r.sqRing[0])) {
			if e := unix.Munmap(r.cqRing); e != nil && err == nil {
				err = e
			}
		}
		r.cqRing = nil
	}
	if r.fd >= 0 {
		if e := unix.Close(r.fd); e != nil && err == nil {
			err = e
		}
		r.fd = -1
	}
	return err
}
