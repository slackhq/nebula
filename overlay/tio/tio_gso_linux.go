package tio

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Space for segmented output. Worst case is many small segments, each paying
// an IP+TCP header. Should be a multiple of 64KiB.
// const tunSegBufSize = 0xffff * 8 TODO larger? config?
const tunSegBufSize = 131072

// tunSegBufCap is the total size we allocate for the per-reader segment
// buffer. It is sized as one worst-case TSO superpacket (tunSegBufSize) plus
// the same again as drain headroom so a Read wake can accumulate
// additional packets after an initial big read without overflowing.
const tunSegBufCap = tunSegBufSize * 2

// tunDrainCap caps how many packets a single Read will accumulate via
// the post-wake drain loop. Sized to soak up a burst of small ACKs while
// bounding how much work a single caller holds before handing off.
const tunDrainCap = 64 //256

// gsoInitialPayIovs is the starting capacity (in payload fragments) of
// Offload.gsoIovs. Sized to cover the default coalesce segment cap without
// any reallocations.
const gsoInitialPayIovs = 66

// validVnetHdr is the 10-byte virtio_net_hdr we prepend to every non-GSO TUN
// write. Only flag set is VIRTIO_NET_HDR_F_DATA_VALID, which marks the skb
// CHECKSUM_UNNECESSARY so the receiving network stack skips L4 checksum
// verification. All packets that reach the plain Write / WriteReject paths
// already carry a valid L4 checksum (either supplied by a remote peer whose
// ciphertext we AEAD-authenticated, or produced by finishChecksum during TSO
// segmentation, or built locally by CreateRejectPacket), so trusting them is
// safe.
var validVnetHdr = [virtioNetHdrLen]byte{unix.VIRTIO_NET_HDR_F_DATA_VALID}

// Offload wraps a TUN file descriptor with poll-based reads. The FD provided will be changed to non-blocking.
// A shared eventfd allows Close to wake all readers blocked in poll.
type Offload struct {
	fd         int
	shutdownFd int
	readPoll   [2]unix.PollFd
	writePoll  [2]unix.PollFd
	closed     atomic.Bool
	readBuf    []byte        // scratch for a single raw read (virtio hdr + superpacket)
	segBuf     []byte        // backing store for segmented output
	segOff     int           // cursor into segBuf for the current Read drain
	pending    [][]byte      // segments returned from the most recent Read
	writeIovs  [2]unix.Iovec // preallocated iovecs for Write (coalescer passthrough); iovs[0] is fixed to validVnetHdr
	// rejectIovs is a second preallocated iovec scratch used exclusively by
	// WriteReject (reject + self-forward from the inside path). It mirrors
	// writeIovs but lets listenIn goroutines emit reject packets without
	// racing with the listenOut coalescer that owns writeIovs.
	rejectIovs [2]unix.Iovec

	// gsoHdrBuf is a per-queue 10-byte scratch for the virtio_net_hdr emitted
	// by WriteGSO. Separate from validVnetHdr so a concurrent non-GSO Write on
	// another queue never observes a half-written header.
	gsoHdrBuf [virtioNetHdrLen]byte
	// gsoIovs is the writev iovec scratch for WriteGSO. Sized to hold the
	// virtio header + IP/TCP header + up to gsoInitialPayIovs payload
	// fragments; grown on demand if a coalescer pushes more.
	gsoIovs []unix.Iovec
}

func newOffload(fd int, shutdownFd int) (*Offload, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}

	out := &Offload{
		fd:         fd,
		shutdownFd: shutdownFd,
		closed:     atomic.Bool{},
		readBuf:    make([]byte, tunReadBufSize),
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},

		segBuf:  make([]byte, tunSegBufCap),
		gsoIovs: make([]unix.Iovec, 2, 2+gsoInitialPayIovs),
	}

	out.writeIovs[0].Base = &validVnetHdr[0]
	out.writeIovs[0].SetLen(virtioNetHdrLen)
	out.rejectIovs[0].Base = &validVnetHdr[0]
	out.rejectIovs[0].SetLen(virtioNetHdrLen)
	out.gsoIovs[0].Base = &out.gsoHdrBuf[0]
	out.gsoIovs[0].SetLen(virtioNetHdrLen)

	return out, nil
}

func (r *Offload) blockOnRead() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(r.readPoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	//always reset these!
	tunEvents := r.readPoll[0].Revents
	shutdownEvents := r.readPoll[1].Revents
	r.readPoll[0].Revents = 0
	r.readPoll[1].Revents = 0
	//do the err check before trusting the potentially bogus bits we just got
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	} else if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (r *Offload) blockOnWrite() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(r.writePoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	//always reset these!
	tunEvents := r.writePoll[0].Revents
	shutdownEvents := r.writePoll[1].Revents
	r.writePoll[0].Revents = 0
	r.writePoll[1].Revents = 0
	//do the err check before trusting the potentially bogus bits we just got
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	} else if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (r *Offload) readRaw(buf []byte) (int, error) {
	for {
		if n, err := unix.Read(r.fd, buf); err == nil {
			return n, nil
		} else if err == unix.EAGAIN {
			if err = r.blockOnRead(); err != nil {
				return 0, err
			}
			continue
		} else if err == unix.EINTR {
			continue
		} else if err == unix.EBADF {
			return 0, os.ErrClosed
		} else {
			return 0, err
		}
	}
}

// Read reads one or more superpackets from the tun and returns the
// resulting packets. The first read blocks via poll; once the fd is known
// readable we drain additional packets non-blocking until the kernel queue
// is empty (EAGAIN), we've collected tunDrainCap packets, or we're out of
// segBuf headroom. This amortizes the poll wake over bursts of small
// packets (e.g. TCP ACKs). Slices point into the Offload's internal buffers
// and are only valid until the next Read or Close on this Queue.
func (r *Offload) Read() ([][]byte, error) {
	r.pending = r.pending[:0]
	r.segOff = 0

	// Initial (blocking) read. Retry on decode errors so a single bad
	// packet does not stall the reader.
	for {
		n, err := r.readRaw(r.readBuf)
		if err != nil {
			return nil, err
		}
		if err := r.decodeRead(n); err != nil {
			// Drop and read again — a bad packet should not kill the reader.
			continue
		}
		break
	}

	// Drain: non-blocking reads until the kernel queue is empty, the drain
	// cap is reached, or segBuf no longer has room for another worst-case
	// superpacket.
	for len(r.pending) < tunDrainCap && tunSegBufCap-r.segOff >= tunSegBufSize {
		n, err := unix.Read(r.fd, r.readBuf)
		if err != nil {
			// EAGAIN / EINTR / anything else: stop draining. We already
			// have a valid batch from the first read.
			break
		}
		if n <= 0 {
			break
		}
		if err := r.decodeRead(n); err != nil {
			// Drop this packet and stop the drain; we'd rather hand off
			// what we have than keep spinning here.
			break
		}
	}

	return r.pending, nil
}

// decodeRead decodes the virtio header plus payload in r.readBuf[:n], appends
// the segments to r.pending, and advances r.segOff by the total scratch used.
// Caller must have already ensured r.vnetHdr is true.
func (r *Offload) decodeRead(n int) error {
	if n < virtioNetHdrLen {
		return fmt.Errorf("short tun read: %d < %d", n, virtioNetHdrLen)
	}
	var hdr VirtioNetHdr
	hdr.decode(r.readBuf[:virtioNetHdrLen])
	before := len(r.pending)
	if err := segmentInto(r.readBuf[virtioNetHdrLen:n], hdr, &r.pending, r.segBuf[r.segOff:]); err != nil {
		return err
	}
	for k := before; k < len(r.pending); k++ {
		r.segOff += len(r.pending[k])
	}
	return nil
}

func (r *Offload) Write(buf []byte) (int, error) {
	return r.writeWithScratch(buf, &r.writeIovs)
}

// WriteReject emits a packet using a dedicated iovec scratch (rejectIovs)
// distinct from the one used by the coalescer's Write path. This avoids a
// data race between the inside (listenIn) goroutine emitting reject or
// self-forward packets and the outside (listenOut) goroutine flushing TCP
// coalescer passthroughs on the same Offload.
func (r *Offload) WriteReject(buf []byte) (int, error) {
	return r.writeWithScratch(buf, &r.rejectIovs)
}

func (r *Offload) writeWithScratch(buf []byte, iovs *[2]unix.Iovec) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	// Point the payload iovec at the caller's buffer. iovs[0] is pre-wired
	// to validVnetHdr during Offload construction so we don't rebuild it here.
	iovs[1].Base = &buf[0]
	iovs[1].SetLen(len(buf))
	return r.rawWrite(unsafe.Slice(&iovs[0], len(iovs)))
}

func (r *Offload) rawWrite(iovs []unix.Iovec) (int, error) {
	for {
		n, _, errno := syscall.Syscall(unix.SYS_WRITEV, uintptr(r.fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
		if errno == 0 {
			if int(n) < virtioNetHdrLen {
				return 0, io.ErrShortWrite
			}
			return int(n) - virtioNetHdrLen, nil
		}
		if errno == unix.EAGAIN {
			if err := r.blockOnWrite(); err != nil {
				return 0, err
			}
			continue
		}
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EBADF {
			return 0, os.ErrClosed
		}
		return 0, errno
	}
}

// GSOSupported reports whether this queue was opened with IFF_VNET_HDR and
// can accept WriteGSO. When false, callers should fall back to per-segment
// Write calls.
func (r *Offload) GSOSupported() bool { return true }

// WriteGSO emits a TCP TSO superpacket in a single writev. hdr is the
// IPv4/IPv6 + TCP header prefix (already finalized — total length, IP csum,
// and TCP pseudo-header partial set by the caller). pays are payload
// fragments whose concatenation forms the full coalesced payload; each
// slice is read-only and must stay valid until return. gsoSize is the MSS;
// every segment except possibly the last is exactly gsoSize bytes.
// csumStart is the byte offset where the TCP header begins within hdr.
func (r *Offload) WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, isV6 bool, csumStart uint16) error {
	if len(hdr) == 0 || len(pays) == 0 {
		return nil
	}

	// Build the virtio_net_hdr. When pays total to <= gsoSize the kernel
	// would produce a single segment; keep NEEDS_CSUM semantics but skip
	// the GSO type so the kernel doesn't spuriously mark this as TSO.
	vhdr := VirtioNetHdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		HdrLen:     uint16(len(hdr)),
		GSOSize:    gsoSize,
		CsumStart:  csumStart,
		CsumOffset: 16, // TCP checksum field lives 16 bytes into the TCP header
	}
	var totalPay int
	for _, p := range pays {
		totalPay += len(p)
	}
	if totalPay > int(gsoSize) {
		if isV6 {
			vhdr.GSOType = unix.VIRTIO_NET_HDR_GSO_TCPV6
		} else {
			vhdr.GSOType = unix.VIRTIO_NET_HDR_GSO_TCPV4
		}
	} else {
		vhdr.GSOType = unix.VIRTIO_NET_HDR_GSO_NONE
		vhdr.GSOSize = 0
	}
	vhdr.encode(r.gsoHdrBuf[:])

	// Build the iovec array: [virtio_hdr, hdr, pays...]. r.gsoIovs[0] is
	// wired to gsoHdrBuf at construction and never changes.
	need := 2 + len(pays)
	if cap(r.gsoIovs) < need {
		grown := make([]unix.Iovec, need)
		grown[0] = r.gsoIovs[0]
		r.gsoIovs = grown
	} else {
		r.gsoIovs = r.gsoIovs[:need]
	}
	r.gsoIovs[1].Base = &hdr[0]
	r.gsoIovs[1].SetLen(len(hdr))
	for i, p := range pays {
		r.gsoIovs[2+i].Base = &p[0]
		r.gsoIovs[2+i].SetLen(len(p))
	}

	_, err := r.rawWrite(r.gsoIovs)
	return err
}

func (r *Offload) Close() error {
	if r.closed.Swap(true) {
		return nil
	}

	//shutdownFd is owned by the container, so we should not close it
	var err error
	if r.fd >= 0 {
		err = unix.Close(r.fd)
		r.fd = -1
	}

	return err
}
