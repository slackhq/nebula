//go:build linux && !android
// +build linux,!android

package tio

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/slackhq/nebula/overlay/tio/virtio"
)

const maxSuperpacketLen = 65535

// tunRxBufSize is the per-Read worst-case footprint inside rxBuf: one kernel-supplied packet body, which is at most ~64 KiB (tunReadBufSize).
// Segmentation happens at encrypt time on a per-routine MTU-sized scratch
// (see SegmentSuperpacket), so rxBuf only holds raw kernel-supplied bytes.
// We round up to give margin for the drain headroom check below.
const tunRxBufSize = 64 * 1024

// tunRxBufCap is the total size we allocate for the per-reader rx buffer.
// Each drain iteration consumes up to tunRxBufSize of headroom for the kernel-supplied bytes.
// Sized to eight such iterations so a single poll wake can drain several TSO/USO superpackets under bulk load,
// amortizing the wake and giving the sendmmsg planner longer same-destination runs.
// Hold latency stays bounded because listenIn flushes its send batch incrementally rather than only at end-of-drain.
const tunRxBufCap = tunRxBufSize * 8

// tunDrainCap caps how many packets a single Read will accumulate via the post-wake drain loop.
// Sized to soak up a burst of small ACKs while bounding how much work a single caller holds before handing off.
const tunDrainCap = 64

// gsoMaxIovs caps the iovec budget WriteGSO assembles per call:
// 3 fixed entries (virtio_net_hdr, IP hdr, transport hdr), plus up to gsoMaxIovs-3 payload fragments.
// Sized comfortably above the typical kernel GSO segment cap (Linux UDP_GRO is 64)
// so realistic coalesced bursts never touch the limit.
// iovecs are tiny (16 bytes), so the entire scratch is 4 KiB.
// WriteGSO returns an error rather than reallocating when a caller exceeds this budget.
const gsoMaxIovs = 256

// validVnetHdr is the 10-byte virtio_net_hdr we prepend to every non-GSO TUN write.
// Only flag set is VIRTIO_NET_HDR_F_DATA_VALID, which marks the skb CHECKSUM_UNNECESSARY
// so the receiving network stack skips L4 checksum verification.
// All packets that reach the plain Write paths already carry a valid L4 checksum, so trusting them is safe.
var validVnetHdr = [virtio.Size]byte{unix.VIRTIO_NET_HDR_F_DATA_VALID}

// Offload wraps a TUN file descriptor with poll-based reads. The FD provided will be changed to non-blocking.
// A shared eventfd allows Close to wake all readers blocked in poll.
type Offload struct {
	fd         int
	shutdownFd int
	closed     atomic.Bool
	rxBuf      []byte   // backing store for kernel-handed packets read this drain
	rxOff      int      // cursor into rxBuf for the current Read drain
	pending    []Packet // packets returned from the most recent Read

	// readVnetScratch holds the 10-byte virtio_net_hdr split off the front of
	// every TUN read via readv(2). Decoupling the header from the packet body
	// lets us read the body directly into rxBuf at the current rxOff with
	// no userspace copy on the GSO_NONE fast path.
	readVnetScratch [virtio.Size]byte
	// readIovs is the readv(2) iovec scratch wired once at construction,
	// iovec[0] points at readVnetScratch
	// iovec[1].Base/Len is updated per read to address the current rxBuf slot.
	readIovs [2]unix.Iovec

	// usoEnabled records whether the kernel agreed to TUN_F_USO* on this FD,
	// so writers can decide whether emitting GSO_UDP_L4 superpackets is safe.
	usoEnabled bool

	// gsoHdrBuf is a per-queue 10-byte scratch for the virtio_net_hdr emitted
	// by WriteGSO. Kept separate from the read-only package-level validVnetHdr
	// so non-GSO Writes can ship that constant directly while WriteGSO
	// rewrites this scratch on every call.
	gsoHdrBuf [virtio.Size]byte
	// gsoIovs is the writev iovec scratch for WriteGSO. Pre-sized to
	// gsoMaxIovs at construction; never grown. WriteGSO returns an error
	// (and drops the call) if a caller hands it more fragments than fit.
	gsoIovs []unix.Iovec
}

func newOffload(fd int, shutdownFd int, usoEnabled bool) (*Offload, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}

	out := &Offload{
		fd:         fd,
		shutdownFd: shutdownFd,
		usoEnabled: usoEnabled,
		closed:     atomic.Bool{},

		rxBuf:   make([]byte, tunRxBufCap),
		gsoIovs: make([]unix.Iovec, 2, gsoMaxIovs),
	}

	out.gsoIovs[0].Base = &out.gsoHdrBuf[0]
	out.gsoIovs[0].SetLen(virtio.Size)

	// readIovs[0] is wired once to the virtio_net_hdr scratch; per-read we
	// only repoint readIovs[1] at the next rxBuf slot (see readPacket).
	out.readIovs[0].Base = &out.readVnetScratch[0]
	out.readIovs[0].SetLen(virtio.Size)

	return out, nil
}

func (r *Offload) blockOnRead() error {
	return blockOn(int32(r.fd), int32(r.shutdownFd), unix.POLLIN)
}

func (r *Offload) blockOnWrite() error {
	return blockOn(int32(r.fd), int32(r.shutdownFd), unix.POLLOUT)
}

// readPacket issues a single readv(2), splitting the virtio_net_hdr off into readVnetScratch
// and reading the packet body directly into rxBuf at the current rxOff.
// Returns the body length (zero virtio header bytes, just the IP packet/superpacket).
// block controls whether EAGAIN is retried via poll: the initial read of a drain blocks; subsequent drain reads do not.
func (r *Offload) readPacket(block bool) (int, error) {
	for {
		r.readIovs[1].Base = &r.rxBuf[r.rxOff]
		r.readIovs[1].SetLen(len(r.rxBuf) - r.rxOff)
		n, _, errno := syscall.Syscall(unix.SYS_READV, uintptr(r.fd), uintptr(unsafe.Pointer(&r.readIovs[0])), uintptr(len(r.readIovs)))
		if errno == 0 {
			if int(n) < virtio.Size {
				return 0, io.ErrShortWrite
			}
			return int(n) - virtio.Size, nil
		}
		if errno == unix.EAGAIN {
			if !block {
				return 0, errno
			}
			if err := r.blockOnRead(); err != nil {
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

// Read returns one or more packets from the tun.
// Each Packet either carries a single ready-to-use IP datagram (GSO zero) or a TSO/USO superpacket plus the GSOInfo a caller needs to segment it (see SegmentSuperpacket).
// The first read blocks via poll; once the fd is known readable we drain additional packets non-blocking until:
//   - the kernel queue is empty (EAGAIN)
//   - we've collected tunDrainCap packets,
//   - or we're out of rxBuf headroom.
//
// This amortizes the poll wake over bursts of small packets (e.g. TCP ACKs).
// Packet.Bytes slices point into the Offload's internal buffer and are only valid until the next Read or Close on this Queue.
func (r *Offload) Read() ([]Packet, error) {
	r.pending = r.pending[:0]
	r.rxOff = 0

	// Initial (blocking) read.
	// Retry on decode errors so a single bad packet does not stall the reader.
	for {
		n, err := r.readPacket(true)
		if err != nil {
			return nil, err
		}
		if err := r.decodeRead(n); err != nil {
			// Drop and read again. A bad packet should not kill the reader.
			continue
		}
		break
	}

	// Drain: non-blocking reads until the kernel queue is empty, the drain
	// cap is reached, or rxBuf no longer has room for another worst-case
	// kernel-supplied packet (tunRxBufSize).
	for len(r.pending) < tunDrainCap && tunRxBufCap-r.rxOff >= tunRxBufSize {
		n, err := r.readPacket(false)
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

// decodeRead processes the packet sitting in rxBuf at rxOff (length pktLen).
// The bytes stay in rxBuf:
//   - for GSO_NONE we slice them as a regular IP datagram (running finishChecksum if NEEDS_CSUM is set);
//   - for TSO/USO superpackets we attach the corrected GSO metadata, so the caller can segment lazily at encrypt time.
//
// rxOff advances by pktLen on success
func (r *Offload) decodeRead(pktLen int) error {
	if pktLen <= 0 {
		return fmt.Errorf("short tun read: %d", pktLen)
	}
	var hdr virtio.Hdr
	hdr.Decode(r.readVnetScratch[:])

	body := r.rxBuf[r.rxOff : r.rxOff+pktLen]

	if hdr.GSOType() == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.Flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			if err := virtio.FinishChecksum(body, hdr); err != nil {
				return err
			}
		}
		r.pending = append(r.pending, Packet{Bytes: body})
		r.rxOff += pktLen
		return nil
	}

	if err := virtio.CheckValid(body, hdr); err != nil {
		return err
	}
	if err := virtio.CorrectHdrLen(body, &hdr); err != nil {
		return err
	}
	proto, err := protoFromGSOType(hdr.GSOType())
	if err != nil {
		return err
	}
	r.pending = append(r.pending, Packet{
		Bytes: body,
		GSO: GSOInfo{
			Size:      hdr.GSOSize,
			HdrLen:    hdr.HdrLen,
			CsumStart: hdr.CsumStart,
			Proto:     proto,
		},
	})
	r.rxOff += pktLen
	return nil
}

func (r *Offload) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	iovs := [2]unix.Iovec{
		{Base: &validVnetHdr[0]},
		{Base: &buf[0]},
	}
	iovs[0].SetLen(virtio.Size)
	iovs[1].SetLen(len(buf))
	return r.rawWrite(unsafe.Slice(&iovs[0], 2))
}

func (r *Offload) rawWrite(iovs []unix.Iovec) (int, error) {
	for {
		n, _, errno := syscall.Syscall(unix.SYS_WRITEV, uintptr(r.fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
		if errno == 0 {
			if int(n) < virtio.Size {
				return 0, io.ErrShortWrite
			}
			return int(n) - virtio.Size, nil
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

// Capabilities reports the offload features negotiated for this Queue. TSO
// is always true for Offload (we only construct it on IFF_VNET_HDR FDs);
// USO is true only when the kernel agreed to TUN_F_USO4|6 at open time (Linux ≥ 6.2).
func (r *Offload) Capabilities() Capabilities {
	return Capabilities{TSO: true, USO: r.usoEnabled}
}

func (r *Offload) WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, proto GSOProto) error {
	if len(pays) == 0 {
		// There are no payload fragments. There is nothing to send.
		return nil
	}
	var csumOff uint16 // csumOff is the offset of the L4 checksum field in transportHdr
	switch proto {
	case GSOProtoUDP:
		csumOff = 6
	case GSOProtoTCP:
		csumOff = 16
	default:
		return fmt.Errorf("unknown GSO proto: %d", proto)
	}
	// Incorrect geometry must cause an error, not a silent drop.
	// No sane packet should ever make it inside this branch.
	if len(hdr) == 0 || len(transportHdr) < int(csumOff)+2 {
		return fmt.Errorf("tio: WriteGSO header too short: ip=%d transport=%d (csum field at %d)", len(hdr), len(transportHdr), csumOff)
	}
	// Make the iovec array: [virtio_hdr, hdr, transportHdr, pays...].
	// The constructor attaches r.gsoIovs[0] to gsoHdrBuf. That entry does not change.
	need := 3 + len(pays)
	if need > cap(r.gsoIovs) {
		return fmt.Errorf("tio: WriteGSO needs %d iovecs but cap is %d", need, cap(r.gsoIovs))
	}
	r.gsoIovs = r.gsoIovs[:need]
	r.gsoIovs[1].Base = &hdr[0]
	r.gsoIovs[1].SetLen(len(hdr))
	r.gsoIovs[2].Base = &transportHdr[0]
	r.gsoIovs[2].SetLen(len(transportHdr))

	// Fill out the payload iovecs and find the GSO geometry:
	segSize := 0
	total := len(hdr) + len(transportHdr)
	n := 3
	for _, p := range pays {
		total += len(p)
		if len(p) == 0 {
			continue //disregard empty payloads, the kernel will reject them.
			//callers already funnel zero-length frames via the not-GSO path, so this should never happen.
		}
		if n == 3 {
			segSize = len(p)
		}
		r.gsoIovs[n].Base = &p[0]
		r.gsoIovs[n].SetLen(len(p))
		n++
	}
	r.gsoIovs = r.gsoIovs[:n]
	segCount := n - 3
	// This check keeps `total` in the uint16 range. Anything larger would wrap around and cause trouble.
	if total > maxSuperpacketLen {
		return fmt.Errorf("tio: WriteGSO superpacket %dB exceeds %d", total, maxSuperpacketLen)
	}
	// gsoType and GSOSize stay zero (GSO_NONE, 0) for single-segment, or an unknown IP version.
	vhdr := virtio.NewHeader(
		unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,   /*flags*/
		unix.VIRTIO_NET_HDR_GSO_NONE,       /*gsoType*/
		uint16(len(hdr)+len(transportHdr)), /*hdrLen*/
		0,                                  /*gsoSize*/
		uint16(len(hdr)),                   /*csumStart*/
		csumOff,                            /*csumOffset*/
	)
	if segCount > 1 {
		ipVer := hdr[0] >> 4
		switch {
		case proto == GSOProtoUDP && (ipVer == 4 || ipVer == 6):
			vhdr.SetGSOType(unix.VIRTIO_NET_HDR_GSO_UDP_L4)
		case ipVer == 6:
			vhdr.SetGSOType(unix.VIRTIO_NET_HDR_GSO_TCPV6)
		case ipVer == 4:
			vhdr.SetGSOType(unix.VIRTIO_NET_HDR_GSO_TCPV4)
		}
		if vhdr.GSOType() != unix.VIRTIO_NET_HDR_GSO_NONE {
			vhdr.GSOSize = uint16(segSize)
		}
	}
	vhdr.Encode(r.gsoHdrBuf[:])

	_, err := r.rawWrite(r.gsoIovs)
	return err
}

func (r *Offload) Close() error {
	if r.closed.Swap(true) {
		return nil
	}

	// shutdownFd is owned by the container, so we should not close it
	// Close the underlying fd but do NOT null r.fd: a reader may still be loading it in readOne, and mutating the field would race that load.
	// That reader gets EBADF -> os.ErrClosed (or wakes via the shutdown eventfd's ppoll first).
	// closed.Swap already guarantees we only close once.
	return unix.Close(r.fd)
}
