//go:build darwin && !ios

package tio

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	_ "unsafe" // for go:linkname

	"github.com/slackhq/nebula/internal/msgx"
	"golang.org/x/sys/unix"
)

// tunMaxPacket is the largest packet utun can return at any device MTU.
const tunMaxPacket = 65535

// tunReadBatch is the most packets one Utun.Read returns.
const tunReadBatch = 64

// tunReadArena is Utun's receive buffer. Draining stops once less than tunMaxPacket of it is left,
// so every readv has room for the largest packet utun can return.
const tunReadArena = 4 * tunMaxPacket

// tunWriteBatch is how many packets one sendmsg_x call may carry.
const tunWriteBatch = 64

// Utun is a darwin utun control socket as a Queue. Every packet crosses the socket behind a 4 byte
// address family prefix, which Read strips and the writes add.
//
// The fd lives in the runtime poller, so Close wakes a Read parked on it; darwin needs no QueueSet
// shutdown fd.
type Utun struct {
	f *os.File
	l *slog.Logger

	// readBuf and readRet are Read's scratch, owned by the single reader.
	readBuf []byte
	readRet [tunReadBatch]Packet

	// noSendmsgX is set when libSystem lacks sendmsg_x or the kernel refuses it; WriteBatch then writes one packet at a time.
	noSendmsgX atomic.Bool
	batchMu    sync.Mutex
	batch      tunBatch
}

// tunBatch is WriteBatch's scratch, guarded by Utun.batchMu. The kernel reads every entry in place.
type tunBatch struct {
	heads [tunWriteBatch][4]byte
	iovs  [tunWriteBatch][2]unix.Iovec
	hdrs  [tunWriteBatch]msgx.Hdr
	pkts  [tunWriteBatch][]byte
}

// NewUtun wraps a utun control socket fd and makes it non-blocking.
// On failure it does NOT close fd: the caller owns fd until NewUtun succeeds, after which Close closes it.
func NewUtun(fd int, l *slog.Logger) (*Utun, error) {
	// Before os.NewFile, which only hands a non-blocking fd to the runtime poller.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set the tun fd to non-blocking mode: %w", err)
	}
	u := &Utun{
		f:       os.NewFile(uintptr(fd), "utun"),
		l:       l,
		readBuf: make([]byte, tunReadArena),
	}
	u.noSendmsgX.Store(!msgx.Available())
	return u, nil
}

// tunWritev and tunReadv are linkname'd to x/sys/unix's libc-routed writev/readv stubs so the
// calls go through libSystem's pinned trampoline. A raw syscall.Syscall(SYS_WRITEV/SYS_READV, ...)
// on darwin/arm64 emits an SVC #0x80 trap (see $GOROOT/src/syscall/asm_darwin_arm64.s), the path
// Apple keeps warning they will eventually disallow. We pull the low-level stubs instead of calling
// unix.Writev/unix.Readv because those take [][]byte and rebuild the []Iovec every call, which
// heap-allocates the header; linkname'ing the stubs lets us hand them our own stack-allocated
// iovecs. See golang/go#78049.

//go:linkname tunWritev golang.org/x/sys/unix.writev
//go:noescape
func tunWritev(fd int, iovecs []unix.Iovec) (n int, err error)

//go:linkname tunReadv golang.org/x/sys/unix.readv
//go:noescape
func tunReadv(fd int, iovecs []unix.Iovec) (n int, err error)

// Read waits for the utun to become readable, then reads packets until it would block, up to
// tunReadBatch, so the caller encrypts and sends them as one batch rather than one per wakeup. Each
// packet is read with its AF prefix scattered away, so the payload lands directly in readBuf.
// An error after at least one packet is dropped in favor of returning those packets; a persistent
// one recurs on the next Read.
func (u *Utun) Read() ([]Packet, error) {
	rc, err := u.f.SyscallConn()
	if err != nil {
		return nil, err
	}

	var head [4]byte
	n, off := 0, 0
	var callErr error
	err = rc.Read(func(fd uintptr) bool {
		for n < tunReadBatch && len(u.readBuf)-off >= tunMaxPacket {
			iovecs := [2]unix.Iovec{
				{Base: &head[0], Len: 4},
				{Base: &u.readBuf[off], Len: uint64(len(u.readBuf) - off)},
			}
			l, e := tunReadv(int(fd), iovecs[:])
			if e != nil {
				if errno, ok := e.(syscall.Errno); ok && errno.Temporary() {
					// Park on the poller only while there is nothing to hand back.
					return n > 0
				}
				callErr = e
				return true
			}
			if l < 4 {
				// A datagram too short to carry the AF prefix, or end of file; stop rather than spin on it.
				return true
			}
			end := off + l - 4
			u.readRet[n] = Packet{Bytes: u.readBuf[off:end:end]}
			n++
			off = end
		}
		return true
	})
	if n > 0 {
		return u.readRet[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, callErr
}

// Write pushes one IP packet onto the utun device. Safe for concurrent use:
// the AF prefix and iovecs are per-call stack state, and the fd write itself
// serializes on the runtime's fd mutex (see the Queue contract in tio.go).
func (u *Utun) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	var head [4]byte
	af, err := tunAF(from)
	if err != nil {
		return 0, err
	}
	head[3] = af

	// Grab rc as a local so the compiler can devirtualize the call and keep the closure on the stack.
	rc, err := u.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var callErr error
	err = rc.Write(func(fd uintptr) bool {
		iovecs := []unix.Iovec{
			{Base: &head[0], Len: 4},
			{Base: &from[0], Len: uint64(len(from))},
		}
		n, callErr = tunWritev(int(fd), iovecs)
		// Type-assert to syscall.Errno so the EAGAIN/EWOULDBLOCK/EINTR check doesn't box the errno
		// constants into error interfaces on every call.
		if errno, ok := callErr.(syscall.Errno); ok && errno.Temporary() {
			return false
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}

	return n - 4, nil
}

// tunAF returns the utun address-family prefix byte for an IP packet.
func tunAF(pkt []byte) (byte, error) {
	switch pkt[0] >> 4 {
	case 4:
		return syscall.AF_INET, nil
	case 6:
		return syscall.AF_INET6, nil
	default:
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}
}

// WriteBatch writes pkts to the utun device with sendmsg_x, xnu's private batched sendmsg, up to
// tunWriteBatch packets per syscall. The kernel still hands each packet to utun on its own, so this
// saves syscalls, not per-packet kernel work. Safe for concurrent use.
//
// An empty packet or one with no IP version is skipped and reported, as Write would. Any other
// error from sendmsg_x means the kernel took an unknown prefix of that call and dropped the rest, so
// it is reported rather than retried, which could deliver packets twice.
//
// Under mbuf exhaustion, sendmsg_x silently drops packets that writev would have delivered: the
// kernel counts each packet as sent once it is copied in, and when a later allocation fails it
// frees that prefix unsent and returns its length as a short count, which is indistinguishable
// from a real one.
func (u *Utun) WriteBatch(pkts [][]byte) error {
	if u.noSendmsgX.Load() {
		return u.writeEach(pkts)
	}

	u.batchMu.Lock()
	defer u.batchMu.Unlock()
	b := &u.batch
	var firstErr error
	for len(pkts) > 0 {
		n := 0
		for len(pkts) > 0 && n < tunWriteBatch {
			p := pkts[0]
			pkts = pkts[1:]
			var af byte
			err := error(syscall.EIO)
			if len(p) > 0 {
				af, err = tunAF(p)
			}
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			b.heads[n] = [4]byte{3: af}
			b.iovs[n] = [2]unix.Iovec{
				{Base: &b.heads[n][0], Len: 4},
				{Base: &p[0], Len: uint64(len(p))},
			}
			b.hdrs[n] = msgx.Hdr{Iov: &b.iovs[n][0], Iovlen: 2}
			b.pkts[n] = p
			n++
		}
		if n == 0 {
			continue
		}

		for off := 0; off < n; {
			sent, err := u.sendmsgX(off, n)
			switch {
			case err == nil && sent > 0:
				// The kernel stops early without an error on a packet larger than the socket's send
				// buffer, or when sending a later packet fails with ENOBUFS; resend the remainder.
				off += sent
			case err == nil:
				if werr := u.writeEach(b.pkts[off:n]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				off = n
			case err == unix.EMSGSIZE:
				// Only the first packet being larger than the socket's send buffer fails the whole call,
				// before the kernel takes any; Write reports that one and the rest go out in the next call.
				if werr := u.writeEach(b.pkts[off : off+1]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				off++
			case err == unix.ENOSYS || err == unix.EPERM || err == unix.EOPNOTSUPP:
				// sendmsg_x is private API: fall back to writev if a kernel or sandbox refuses it.
				if u.noSendmsgX.CompareAndSwap(false, true) {
					u.l.Warn("sendmsg_x unavailable on the tun device, writing one packet per syscall", "error", err)
				}
				if werr := u.writeEach(b.pkts[off:n]); werr != nil && firstErr == nil {
					firstErr = werr
				}
				clear(b.iovs[:n])
				clear(b.pkts[:n])
				if werr := u.writeEach(pkts); werr != nil && firstErr == nil {
					firstErr = werr
				}
				return firstErr
			default:
				if firstErr == nil {
					firstErr = err
				}
				off = n
			}
		}
		clear(b.iovs[:n])
		clear(b.pkts[:n])
	}
	return firstErr
}

// sendmsgX hands entries off through n-1 of u.batch to sendmsg_x and returns how many the kernel took.
func (u *Utun) sendmsgX(off, n int) (int, error) {
	rc, err := u.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var sent int
	var errno syscall.Errno
	err = rc.Write(func(fd uintptr) bool {
		sent, errno = msgx.Send(fd, u.batch.hdrs[off:n], 0)
		// sendmsg_x reports EAGAIN only when it took nothing; a partial batch returns its count.
		return !errno.Temporary()
	})
	if err != nil {
		return 0, err
	}
	if errno != 0 {
		return 0, errno
	}
	return sent, nil
}

// writeEach writes pkts one at a time with Write.
func (u *Utun) writeEach(pkts [][]byte) error {
	var firstErr error
	for _, p := range pkts {
		if _, err := u.Write(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (u *Utun) Close() error {
	return u.f.Close()
}
