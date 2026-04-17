//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package overlay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tunFile wraps a TUN file descriptor with poll-based reads. The FD provided will be changed to non-blocking.
// A shared eventfd allows Close to wake all readers blocked in poll.
type tunFile struct {
	fd         int
	shutdownFd int
	lastOne    bool
	readPoll   [2]unix.PollFd
	writePoll  [2]unix.PollFd
	closed     bool

	// vnetHdr is true when this fd was opened with IFF_VNET_HDR and the
	// kernel successfully accepted TUNSETOFFLOAD. Reads include a leading
	// virtio_net_hdr and may carry a TSO superpacket we must segment;
	// writes must prepend a zeroed virtio_net_hdr.
	vnetHdr    bool
	readBuf    []byte   // scratch for a single raw read (virtio hdr + superpacket)
	segBuf     []byte   // backing store for segmented output
	segOff     int      // cursor into segBuf for the current ReadBatch drain
	pending    [][]byte // segments waiting to be drained by Read
	pendingIdx int
	writeIovs  [2]unix.Iovec // preallocated iovecs for vnetHdr writes; iovs[0] is fixed to zeroVnetHdr

	// gsoHdrBuf is a per-queue 10-byte scratch for the virtio_net_hdr emitted
	// by WriteGSO. Separate from zeroVnetHdr so a concurrent non-GSO Write on
	// another queue never observes a half-written header.
	gsoHdrBuf [virtioNetHdrLen]byte
	// gsoIovs is the writev iovec scratch for WriteGSO. Sized to hold the
	// virtio header + IP/TCP header + up to gsoInitialPayIovs payload
	// fragments; grown on demand if a coalescer pushes more.
	gsoIovs []unix.Iovec
}

// gsoInitialPayIovs is the starting capacity (in payload fragments) of
// tunFile.gsoIovs. Sized to cover the default coalesce segment cap without
// any reallocations.
const gsoInitialPayIovs = 66

// zeroVnetHdr is the 10-byte virtio_net_hdr we prepend to every TUN write when
// IFF_VNET_HDR is active. All-zero signals "no GSO, no checksum offload"; the
// kernel accepts the packet as-is.
var zeroVnetHdr [virtioNetHdrLen]byte

// newFriend makes a tunFile for a MultiQueueReader that copies the shutdown eventfd from the parent tun
func (r *tunFile) newFriend(fd int) (*tunFile, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}
	out := &tunFile{
		fd:         fd,
		shutdownFd: r.shutdownFd,
		vnetHdr:    r.vnetHdr,
		readBuf:    make([]byte, tunReadBufSize),
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(r.shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(r.shutdownFd), Events: unix.POLLIN},
		},
	}
	if r.vnetHdr {
		out.segBuf = make([]byte, tunSegBufCap)
		out.writeIovs[0].Base = &zeroVnetHdr[0]
		out.writeIovs[0].SetLen(virtioNetHdrLen)
		out.gsoIovs = make([]unix.Iovec, 2, 2+gsoInitialPayIovs)
		out.gsoIovs[0].Base = &out.gsoHdrBuf[0]
		out.gsoIovs[0].SetLen(virtioNetHdrLen)
	}
	return out, nil
}

func newTunFd(fd int, vnetHdr bool) (*tunFile, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("failed to set tun fd non-blocking: %w", err)
	}

	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to create eventfd: %w", err)
	}

	out := &tunFile{
		fd:         fd,
		shutdownFd: shutdownFd,
		lastOne:    true,
		vnetHdr:    vnetHdr,
		readBuf:    make([]byte, tunReadBufSize),
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
	}
	if vnetHdr {
		out.segBuf = make([]byte, tunSegBufCap)
		out.writeIovs[0].Base = &zeroVnetHdr[0]
		out.writeIovs[0].SetLen(virtioNetHdrLen)
		out.gsoIovs = make([]unix.Iovec, 2, 2+gsoInitialPayIovs)
		out.gsoIovs[0].Base = &out.gsoHdrBuf[0]
		out.gsoIovs[0].SetLen(virtioNetHdrLen)
	}

	return out, nil
}

func (r *tunFile) blockOnRead() error {
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

func (r *tunFile) blockOnWrite() error {
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

func (r *tunFile) readRaw(buf []byte) (int, error) {
	for {
		if n, err := unix.Read(r.fd, buf); err == nil {
			return n, nil
		} else if err == unix.EAGAIN {
			if err = r.blockOnRead(); err != nil {
				return 0, err
			}
			continue
		} else {
			return 0, err
		}
	}
}

// ReadBatch reads one or more superpackets from the tun and returns the
// resulting packets. The first read blocks via poll; once the fd is known
// readable we drain additional packets non-blocking until the kernel queue
// is empty (EAGAIN), we've collected tunDrainCap packets, or we're out of
// segBuf headroom. This amortizes the poll wake over bursts of small
// packets (e.g. TCP ACKs). Slices point into the tunFile's internal buffers
// and are only valid until the next ReadBatch / Read / Close on this Queue.
func (r *tunFile) ReadBatch() ([][]byte, error) {
	r.pending = r.pending[:0]
	r.pendingIdx = 0
	r.segOff = 0

	// Initial (blocking) read. Retry on decode errors so a single bad
	// packet does not stall the reader.
	for {
		n, err := r.readRaw(r.readBuf)
		if err != nil {
			return nil, err
		}
		if !r.vnetHdr {
			r.pending = append(r.pending, r.readBuf[:n])
			// Non-vnetHdr mode shares one readBuf so we can't drain safely
			// without copying; return the single packet as before.
			return r.pending, nil
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
func (r *tunFile) decodeRead(n int) error {
	if n < virtioNetHdrLen {
		return fmt.Errorf("short tun read: %d < %d", n, virtioNetHdrLen)
	}
	var hdr virtioNetHdr
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

// Read drains segments produced by the last ReadBatch one at a time; when the
// batch is exhausted it fetches a fresh one. Kept for io.Reader compatibility;
// batch-aware callers should use ReadBatch directly.
func (r *tunFile) Read(buf []byte) (int, error) {
	for {
		if r.pendingIdx < len(r.pending) {
			seg := r.pending[r.pendingIdx]
			r.pendingIdx++
			if len(seg) > len(buf) {
				return 0, io.ErrShortBuffer
			}
			return copy(buf, seg), nil
		}
		if _, err := r.ReadBatch(); err != nil {
			return 0, err
		}
	}
}

func (r *tunFile) Write(buf []byte) (int, error) {
	if !r.vnetHdr {
		for {
			if n, err := unix.Write(r.fd, buf); err == nil {
				return n, nil
			} else if err == unix.EAGAIN {
				if err = r.blockOnWrite(); err != nil {
					return 0, err
				}
				continue
			} else if err == unix.EINTR {
				continue
			} else {
				return 0, err
			}
		}
	}

	if len(buf) == 0 {
		return 0, nil
	}
	// Point the payload iovec at the caller's buffer. iovs[0] is pre-wired
	// to zeroVnetHdr during tunFile construction so we don't rebuild it here.
	r.writeIovs[1].Base = &buf[0]
	r.writeIovs[1].SetLen(len(buf))
	iovPtr := uintptr(unsafe.Pointer(&r.writeIovs[0]))
	// The TUN fd is non-blocking (set in newTunFd / newFriend), so writev
	// either completes promptly or returns EAGAIN — it cannot park the
	// goroutine inside the kernel. That lets us use syscall.RawSyscall and
	// skip the runtime.entersyscall / exitsyscall bookkeeping on every
	// packet; we only pay that cost when we fall through to blockOnWrite.
	for {
		n, _, errno := syscall.RawSyscall(unix.SYS_WRITEV, uintptr(r.fd), iovPtr, 2)
		if errno == 0 {
			runtime.KeepAlive(buf)
			if int(n) < virtioNetHdrLen {
				return 0, io.ErrShortWrite
			}
			return int(n) - virtioNetHdrLen, nil
		}
		if errno == unix.EAGAIN {
			runtime.KeepAlive(buf)
			if err := r.blockOnWrite(); err != nil {
				return 0, err
			}
			continue
		}
		if errno == unix.EINTR {
			continue
		}
		runtime.KeepAlive(buf)
		return 0, errno
	}
}

// GSOSupported reports whether this queue was opened with IFF_VNET_HDR and
// can accept WriteGSO. When false, callers should fall back to per-segment
// Write calls.
func (r *tunFile) GSOSupported() bool { return r.vnetHdr }

// WriteGSO emits a TCP TSO superpacket in a single writev. hdr is the
// IPv4/IPv6 + TCP header prefix (already finalized — total length, IP csum,
// and TCP pseudo-header partial set by the caller). pays are payload
// fragments whose concatenation forms the full coalesced payload; each
// slice is read-only and must stay valid until return. gsoSize is the MSS;
// every segment except possibly the last is exactly gsoSize bytes.
// csumStart is the byte offset where the TCP header begins within hdr.
func (r *tunFile) WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, isV6 bool, csumStart uint16) error {
	if !r.vnetHdr {
		return fmt.Errorf("WriteGSO called on tun without IFF_VNET_HDR")
	}
	if len(hdr) == 0 || len(pays) == 0 {
		return nil
	}

	// Build the virtio_net_hdr. When pays total to <= gsoSize the kernel
	// would produce a single segment; keep NEEDS_CSUM semantics but skip
	// the GSO type so the kernel doesn't spuriously mark this as TSO.
	vhdr := virtioNetHdr{
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

	iovPtr := uintptr(unsafe.Pointer(&r.gsoIovs[0]))
	iovCnt := uintptr(len(r.gsoIovs))
	for {
		n, _, errno := syscall.RawSyscall(unix.SYS_WRITEV, uintptr(r.fd), iovPtr, iovCnt)
		if errno == 0 {
			runtime.KeepAlive(hdr)
			runtime.KeepAlive(pays)
			if int(n) < virtioNetHdrLen {
				return io.ErrShortWrite
			}
			return nil
		}
		if errno == unix.EAGAIN {
			runtime.KeepAlive(hdr)
			runtime.KeepAlive(pays)
			if err := r.blockOnWrite(); err != nil {
				return err
			}
			continue
		}
		if errno == unix.EINTR {
			continue
		}
		runtime.KeepAlive(hdr)
		runtime.KeepAlive(pays)
		return errno
	}
}

func (r *tunFile) wakeForShutdown() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, err := unix.Write(int(r.readPoll[1].Fd), buf[:])
	return err
}

func (r *tunFile) Close() error {
	if r.closed { // avoid closing more than once. Technically a fd could get re-used, which would be a problem
		return nil
	}
	r.closed = true
	if r.lastOne {
		_ = unix.Close(r.shutdownFd)
	}
	return unix.Close(r.fd)
}

type tun struct {
	*tunFile
	readers     []*tunFile
	closeLock   sync.Mutex
	Device      string
	vpnNetworks []netip.Prefix
	MaxMTU      int
	DefaultMTU  int
	TXQueueLen  int
	deviceIndex int
	ioctlFd     uintptr

	Routes                    atomic.Pointer[[]Route]
	routeTree                 atomic.Pointer[bart.Table[routing.Gateways]]
	routeChan                 chan struct{}
	useSystemRoutes           bool
	useSystemRoutesBufferSize int

	// These are routes learned from `tun.use_system_route_table`
	// stored here to make it easier to restore them after a reload
	routesFromSystem     map[netip.Prefix]routing.Gateways
	routesFromSystemLock sync.Mutex

	l *logrus.Logger
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	pad  [8]byte
}

type ifreqQLEN struct {
	Name  [16]byte
	Value int32
	pad   [8]byte
}

func newTunFromFd(c *config.C, l *logrus.Logger, deviceFd int, vpnNetworks []netip.Prefix) (*tun, error) {
	// We don't know what flags the caller opened this fd with and can't turn
	// on IFF_VNET_HDR after TUNSETIFF, so skip offload on inherited fds.
	t, err := newTunGeneric(c, l, deviceFd, false, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = "tun0"

	return t, nil
}

// openTunDev opens /dev/net/tun, creating the device node first if it's
// missing (docker containers occasionally omit it).
func openTunDev() (int, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err == nil {
		return fd, nil
	}
	if !os.IsNotExist(err) {
		return -1, err
	}
	if err = os.MkdirAll("/dev/net", 0755); err != nil {
		return -1, fmt.Errorf("/dev/net/tun doesn't exist, failed to mkdir -p /dev/net: %w", err)
	}
	if err = unix.Mknod("/dev/net/tun", unix.S_IFCHR|0600, int(unix.Mkdev(10, 200))); err != nil {
		return -1, fmt.Errorf("failed to create /dev/net/tun: %w", err)
	}
	fd, err = unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("created /dev/net/tun, but still failed: %w", err)
	}
	return fd, nil
}

// tunSetIff runs TUNSETIFF with the given flags and returns the kernel-chosen
// device name on success.
func tunSetIff(fd int, name string, flags uint16) (string, error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], name)
	if err := ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return "", err
	}
	return strings.Trim(string(req.Name[:]), "\x00"), nil
}

// tsoOffloadFlags are the TUN_F_* bits we ask the kernel to enable when a
// TSO-capable TUN is available. CSUM is required as a prerequisite for TSO.
const tsoOffloadFlags = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, multiqueue bool) (*tun, error) {
	baseFlags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if multiqueue {
		baseFlags |= unix.IFF_MULTI_QUEUE
	}
	nameStr := c.GetString("tun.dev", "")

	// First try to open with IFF_VNET_HDR + TUNSETOFFLOAD so we can receive
	// TSO superpackets. If either step fails (older kernel, unprivileged
	// container, etc.) we close and fall back to a plain TUN.
	fd, err := openTunDev()
	if err != nil {
		return nil, err
	}
	vnetHdr := true
	name, err := tunSetIff(fd, nameStr, baseFlags|unix.IFF_VNET_HDR|unix.IFF_NAPI)
	if err != nil {
		_ = unix.Close(fd)
		vnetHdr = false
	} else if err = ioctl(uintptr(fd), unix.TUNSETOFFLOAD, uintptr(tsoOffloadFlags)); err != nil {
		l.WithError(err).Warn("Failed to enable TUN offload (TSO); proceeding without virtio headers")
		_ = unix.Close(fd)
		vnetHdr = false
	}

	if !vnetHdr {
		fd, err = openTunDev()
		if err != nil {
			return nil, err
		}
		name, err = tunSetIff(fd, nameStr, baseFlags)
		if err != nil {
			_ = unix.Close(fd)
			return nil, &NameError{Name: nameStr, Underlying: err}
		}
	}

	t, err := newTunGeneric(c, l, fd, vnetHdr, vpnNetworks)
	if err != nil {
		return nil, err
	}

	t.Device = name

	return t, nil
}

// newTunGeneric does all the stuff common to different tun initialization paths. It will close your files on error.
func newTunGeneric(c *config.C, l *logrus.Logger, fd int, vnetHdr bool, vpnNetworks []netip.Prefix) (*tun, error) {
	tfd, err := newTunFd(fd, vnetHdr)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	t := &tun{
		tunFile:                   tfd,
		readers:                   []*tunFile{tfd},
		closeLock:                 sync.Mutex{},
		vpnNetworks:               vpnNetworks,
		TXQueueLen:                c.GetInt("tun.tx_queue", 500),
		useSystemRoutes:           c.GetBool("tun.use_system_route_table", false),
		useSystemRoutesBufferSize: c.GetInt("tun.use_system_route_table_buffer_size", 0),
		routesFromSystem:          map[netip.Prefix]routing.Gateways{},
		l:                         l,
	}

	if err = t.reload(c, true); err != nil {
		_ = t.Close()
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	routeChange, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !routeChange && !c.HasChanged("tun.mtu") {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, true)
	if err != nil {
		return err
	}

	// Bring along any routes learned from the system route table on reload
	t.routesFromSystemLock.Lock()
	for dst, gw := range t.routesFromSystem {
		routeTree.Insert(dst, gw)
	}
	t.routesFromSystemLock.Unlock()

	oldDefaultMTU := t.DefaultMTU
	oldMaxMTU := t.MaxMTU
	newDefaultMTU := c.GetInt("tun.mtu", DefaultMTU)
	newMaxMTU := newDefaultMTU
	for i, r := range routes {
		if r.MTU == 0 {
			routes[i].MTU = newDefaultMTU
		}

		if r.MTU > t.MaxMTU {
			newMaxMTU = r.MTU
		}
	}

	t.MaxMTU = newMaxMTU
	t.DefaultMTU = newDefaultMTU

	// Teach nebula how to handle the routes before establishing them in the system table
	oldRoutes := t.Routes.Swap(&routes)
	t.routeTree.Store(routeTree)

	if !initial {
		if oldMaxMTU != newMaxMTU {
			t.setMTU()
			t.l.Infof("Set max MTU to %v was %v", t.MaxMTU, oldMaxMTU)
		}

		if oldDefaultMTU != newDefaultMTU {
			for i := range t.vpnNetworks {
				err := t.setDefaultRoute(t.vpnNetworks[i])
				if err != nil {
					t.l.Warn(err)
				} else {
					t.l.Infof("Set default MTU to %v was %v", t.DefaultMTU, oldDefaultMTU)
				}
			}
		}

		// Remove first, if the system removes a wanted route hopefully it will be re-added next
		t.removeRoutes(findRemovedRoutes(routes, *oldRoutes))

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true)
		if err != nil {
			// This should never be called since addRoutes should log its own errors in a reload condition
			util.LogWithContextIfNeeded("Failed to refresh routes", err, t.l)
		}
	}

	return nil
}

func (t *tun) SupportsMultiqueue() bool {
	return true
}

func (t *tun) NewMultiQueueReader() (Queue, error) {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()

	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	if t.vnetHdr {
		flags |= unix.IFF_VNET_HDR | unix.IFF_NAPI
	}
	if _, err = tunSetIff(fd, t.Device, flags); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if t.vnetHdr {
		if err = ioctl(uintptr(fd), unix.TUNSETOFFLOAD, uintptr(tsoOffloadFlags)); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("failed to enable offload on multiqueue tun fd: %w", err)
		}
	}

	out, err := t.tunFile.newFriend(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	t.readers = append(t.readers, out)

	return out, nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func hasNetlinkAddr(al []*netlink.Addr, x netlink.Addr) bool {
	for i := range al {
		if al[i].Equal(x) {
			return true
		}
	}
	return false
}

// addIPs uses netlink to add all addresses that don't exist, then it removes ones that should not be there
func (t *tun) addIPs(link netlink.Link) error {
	newAddrs := make([]*netlink.Addr, len(t.vpnNetworks))
	for i := range t.vpnNetworks {
		newAddrs[i] = &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   t.vpnNetworks[i].Addr().AsSlice(),
				Mask: net.CIDRMask(t.vpnNetworks[i].Bits(), t.vpnNetworks[i].Addr().BitLen()),
			},
			Label: t.vpnNetworks[i].Addr().Zone(),
		}
	}

	//add all new addresses
	for i := range newAddrs {
		//AddrReplace still adds new IPs, but if their properties change it will change them as well
		if err := netlink.AddrReplace(link, newAddrs[i]); err != nil {
			return err
		}
	}

	//iterate over remainder, remove whoever shouldn't be there
	al, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get tun address list: %s", err)
	}

	for i := range al {
		if hasNetlinkAddr(newAddrs, al[i]) {
			continue
		}
		err = netlink.AddrDel(link, &al[i])
		if err != nil {
			t.l.WithError(err).Error("failed to remove address from tun address list")
		} else {
			t.l.WithField("removed", al[i].String()).Info("removed address not listed in cert(s)")
		}
	}

	return nil
}

func (t *tun) Activate() error {
	devName := t.deviceBytes()

	if t.useSystemRoutes {
		t.watchRoutes()
	}

	s, err := unix.Socket(
		unix.AF_INET, //because everything we use t.ioctlFd for is address family independent, this is fine
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	t.ioctlFd = uintptr(s)

	// Set the device name
	ifrf := ifReq{Name: devName}
	if err = ioctl(t.ioctlFd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set tun device name: %s", err)
	}

	link, err := netlink.LinkByName(t.Device)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	t.deviceIndex = link.Attrs().Index

	// Setup our default MTU
	t.setMTU()

	// Set the transmit queue length
	ifrq := ifreqQLEN{Name: devName, Value: int32(t.TXQueueLen)}
	if err = ioctl(t.ioctlFd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		// If we can't set the queue length nebula will still work but it may lead to packet loss
		t.l.WithError(err).Error("Failed to set tun tx queue length")
	}

	const modeNone = 1
	if err = netlink.LinkSetIP6AddrGenMode(link, modeNone); err != nil {
		t.l.WithError(err).Warn("Failed to disable link local address generation")
	}

	if err = t.addIPs(link); err != nil {
		return err
	}

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(t.ioctlFd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	//set route MTU
	for i := range t.vpnNetworks {
		if err = t.setDefaultRoute(t.vpnNetworks[i]); err != nil {
			return fmt.Errorf("failed to set default route MTU: %w", err)
		}
	}

	// Set the routes
	if err = t.addRoutes(false); err != nil {
		return err
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(t.ioctlFd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	return nil
}

func (t *tun) setMTU() {
	// Set the MTU on the device
	ifm := ifreqMTU{Name: t.deviceBytes(), MTU: int32(t.MaxMTU)}
	if err := ioctl(t.ioctlFd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		// This is currently a non fatal condition because the route table must have the MTU set appropriately as well
		t.l.WithError(err).Error("Failed to set tun mtu")
	}
}

func (t *tun) setDefaultRoute(cidr netip.Prefix) error {
	dr := &net.IPNet{
		IP:   cidr.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(cidr.Bits(), cidr.Addr().BitLen()),
	}

	nr := netlink.Route{
		LinkIndex: t.deviceIndex,
		Dst:       dr,
		MTU:       t.DefaultMTU,
		AdvMSS:    t.advMSS(Route{}),
		Scope:     unix.RT_SCOPE_LINK,
		Src:       net.IP(cidr.Addr().AsSlice()),
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err := netlink.RouteReplace(&nr)
	if err != nil {
		t.l.WithError(err).WithField("cidr", cidr).Warn("Failed to set default route MTU, retrying")
		//retry twice more -- on some systems there appears to be a race condition where if we set routes too soon, netlink says `invalid argument`
		for i := 0; i < 2; i++ {
			time.Sleep(100 * time.Millisecond)
			err = netlink.RouteReplace(&nr)
			if err == nil {
				break
			} else {
				t.l.WithError(err).WithField("cidr", cidr).WithField("mtu", t.DefaultMTU).Warn("Failed to set default route MTU, retrying")
			}
		}
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on the default route %v; %v", t.DefaultMTU, dr, err)
		}
	}

	return nil
}

func (t *tun) addRoutes(logErrors bool) error {
	// Path routes
	routes := *t.Routes.Load()
	for _, r := range routes {
		if !r.Install {
			continue
		}

		dr := &net.IPNet{
			IP:   r.Cidr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(r.Cidr.Bits(), r.Cidr.Addr().BitLen()),
		}

		nr := netlink.Route{
			LinkIndex: t.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err := netlink.RouteReplace(&nr)
		if err != nil {
			retErr := util.NewContextualError("Failed to add route", map[string]any{"route": r}, err)
			if logErrors {
				retErr.Log(t.l)
			} else {
				return retErr
			}
		} else {
			t.l.WithField("route", r).Info("Added route")
		}
	}

	return nil
}

func (t *tun) removeRoutes(routes []Route) {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		dr := &net.IPNet{
			IP:   r.Cidr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(r.Cidr.Bits(), r.Cidr.Addr().BitLen()),
		}

		nr := netlink.Route{
			LinkIndex: t.deviceIndex,
			Dst:       dr,
			MTU:       r.MTU,
			AdvMSS:    t.advMSS(r),
			Scope:     unix.RT_SCOPE_LINK,
		}

		if r.Metric > 0 {
			nr.Priority = r.Metric
		}

		err := netlink.RouteDel(&nr)
		if err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) advMSS(r Route) int {
	mtu := r.MTU
	if r.MTU == 0 {
		mtu = t.DefaultMTU
	}

	// We only need to set advmss if the route MTU does not match the device MTU
	if mtu != t.MaxMTU {
		return mtu - 40
	}
	return 0
}

func (t *tun) watchRoutes() {
	rch := make(chan netlink.RouteUpdate)
	doneChan := make(chan struct{})

	netlinkOptions := netlink.RouteSubscribeOptions{
		ReceiveBufferSize:      t.useSystemRoutesBufferSize,
		ReceiveBufferForceSize: t.useSystemRoutesBufferSize != 0,
		ErrorCallback:          func(e error) { t.l.WithError(e).Errorf("netlink error") },
	}

	if err := netlink.RouteSubscribeWithOptions(rch, doneChan, netlinkOptions); err != nil {
		t.l.WithError(err).Errorf("failed to subscribe to system route changes")
		return
	}

	t.routeChan = doneChan

	go func() {
		for {
			select {
			case r, ok := <-rch:
				if ok {
					t.updateRoutes(r)
				} else {
					// may be should do something here as
					// netlink stops sending updates
					return
				}
			case <-doneChan:
				// netlink.RouteSubscriber will close the rch for us
				return
			}
		}
	}()
}

func (t *tun) isGatewayInVpnNetworks(gwAddr netip.Addr) bool {
	withinNetworks := false
	for i := range t.vpnNetworks {
		if t.vpnNetworks[i].Contains(gwAddr) {
			withinNetworks = true
			break
		}
	}

	return withinNetworks
}

func (t *tun) getGatewaysFromRoute(r *netlink.Route) routing.Gateways {
	var gateways routing.Gateways

	link, err := netlink.LinkByName(t.Device)
	if err != nil {
		t.l.WithField("deviceName", t.Device).Error("Ignoring route update: failed to get link by name")
		return gateways
	}

	// If this route is relevant to our interface and there is a gateway then add it
	if r.LinkIndex == link.Attrs().Index {
		gwAddr, ok := getGatewayAddr(r.Gw, r.Via)
		if ok {
			if t.isGatewayInVpnNetworks(gwAddr) {
				gateways = append(gateways, routing.NewGateway(gwAddr, 1))
			} else {
				// Gateway isn't in our overlay network, ignore
				t.l.WithField("route", r).Debug("Ignoring route update, gateway is not in our network")
			}
		} else {
			t.l.WithField("route", r).Debug("Ignoring route update, invalid gateway or via address")
		}
	}

	for _, p := range r.MultiPath {
		// If this route is relevant to our interface and there is a gateway then add it
		if p.LinkIndex == link.Attrs().Index {
			gwAddr, ok := getGatewayAddr(p.Gw, p.Via)
			if ok {
				if t.isGatewayInVpnNetworks(gwAddr) {
					gateways = append(gateways, routing.NewGateway(gwAddr, p.Hops+1))
				} else {
					// Gateway isn't in our overlay network, ignore
					t.l.WithField("route", r).Debug("Ignoring route update, gateway is not in our network")
				}
			} else {
				t.l.WithField("route", r).Debug("Ignoring route update, invalid gateway or via address")
			}
		}
	}

	routing.CalculateBucketsForGateways(gateways)
	return gateways
}

func getGatewayAddr(gw net.IP, via netlink.Destination) (netip.Addr, bool) {
	// Try to use the old RTA_GATEWAY first
	gwAddr, ok := netip.AddrFromSlice(gw)
	if !ok {
		// Fallback to the new RTA_VIA
		rVia, ok := via.(*netlink.Via)
		if ok {
			gwAddr, ok = netip.AddrFromSlice(rVia.Addr)
		}
	}

	if gwAddr.IsValid() {
		gwAddr = gwAddr.Unmap()
		return gwAddr, true
	}

	return netip.Addr{}, false
}

func (t *tun) updateRoutes(r netlink.RouteUpdate) {
	gateways := t.getGatewaysFromRoute(&r.Route)
	if len(gateways) == 0 {
		// No gateways relevant to our network, no routing changes required.
		t.l.WithField("route", r).Debug("Ignoring route update, no gateways")
		return
	}

	if r.Dst == nil {
		t.l.WithField("route", r).Debug("Ignoring route update, no destination address")
		return
	}

	dstAddr, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		t.l.WithField("route", r).Debug("Ignoring route update, invalid destination address")
		return
	}

	ones, _ := r.Dst.Mask.Size()
	dst := netip.PrefixFrom(dstAddr, ones)

	newTree := t.routeTree.Load().Clone()

	t.routesFromSystemLock.Lock()
	if r.Type == unix.RTM_NEWROUTE {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Adding route")
		t.routesFromSystem[dst] = gateways
		newTree.Insert(dst, gateways)

	} else {
		t.l.WithField("destination", dst).WithField("via", gateways).Info("Removing route")
		delete(t.routesFromSystem, dst)
		newTree.Delete(dst)
	}
	t.routesFromSystemLock.Unlock()
	t.routeTree.Store(newTree)
}

func (t *tun) Close() error {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()

	if t.routeChan != nil {
		close(t.routeChan)
		t.routeChan = nil
	}

	// Signal all readers blocked in poll to wake up and exit
	_ = t.tunFile.wakeForShutdown()

	if t.ioctlFd > 0 {
		_ = unix.Close(int(t.ioctlFd))
		t.ioctlFd = 0
	}

	for i := range t.readers {
		if i == 0 {
			continue //we want to close the zeroth reader last
		}
		err := t.readers[i].Close()
		if err != nil {
			t.l.WithField("reader", i).WithError(err).Error("error closing tun reader")
		} else {
			t.l.WithField("reader", i).Info("closed tun reader")
		}
	}

	//this is t.readers[0] too
	err := t.tunFile.Close()
	if err != nil {
		t.l.WithField("reader", 0).WithError(err).Error("error closing tun reader")
	} else {
		t.l.WithField("reader", 0).Info("closed tun reader")
	}
	return err
}
