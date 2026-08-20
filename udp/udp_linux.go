//go:build !android && !e2e_testing

package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	sysFd  int
	closed atomic.Bool
	isV4   bool
	l      *slog.Logger
	batch  int

	// bw owns the sendmmsg/UDP-GSO transmit path: the per-queue write
	// scratch and the GSO capability state probed at socket creation. See
	// udp_linux_writebatch.go.
	bw *batchWriter

	groSupported bool
}

func NewListener(l *slog.Logger, s Settings) (Conn, error) {
	af := unix.AF_INET6
	if s.Listen.Addr().Is4() {
		af = unix.AF_INET
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("unable to open socket: %w", err)
	}

	if s.Multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %w", err)
		}
	}

	var sa unix.Sockaddr
	port := int(s.Listen.Port())
	if s.Listen.Addr().Is4() {
		sa4 := &unix.SockaddrInet4{Port: port}
		sa4.Addr = s.Listen.Addr().As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		sa6.Addr = s.Listen.Addr().As16()
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("unable to bind to socket: %w", err)
	}

	out := &StdConn{sysFd: fd, isV4: s.Listen.Addr().Is4(), l: l, batch: s.Batch}

	out.bw = newBatchWriter(fd, out.isV4, l, s.Offloads)

	// GRO coalesces same-flow datagrams into superpackets that must be split back apart via the delivered gso_size cmsg
	// batch == 1 means the caller wants plain single-datagram reads with MTU-sized buffers, so leave it off.
	if s.Batch > 1 && s.Offloads {
		out.prepareGRO()
	}

	return out, nil
}

// udpGROBufferSize sizes the per-entry recvmmsg buffer when UDP_GRO is on.
// The kernel stitches a run of same-flow datagrams into a single skb whose
// length is bounded by sk_gso_max_size (65535)
const udpGROBufferSize = 65535

// udpGROCmsgPayload is the size of the UDP_GRO cmsg data delivered by the
// kernel: a single int (gso_size in bytes). See udp_cmsg_recv() in net/ipv4/udp.c.
const udpGROCmsgPayload = 4

// prepareGRO turns on UDP_GRO so the kernel coalesces consecutive same-flow
// datagrams into one recvmmsg entry, with a cmsg carrying the gso_size used
// to split them back apart on the application side.
func (u *StdConn) prepareGRO() {
	err := unix.SetsockoptInt(u.sysFd, unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	if err != nil {
		u.l.Info("udp: GRO disabled", "reason", "kernel rejected probe", "error", err)
		recordCapability("udp.gro.enabled", false)
		return
	}
	u.groSupported = true
	u.l.Info("udp: GRO enabled")
	recordCapability("udp.gro.enabled", true)
}

// recordCapability registers (or updates) a boolean gauge for one of the
// kernel-feature probes. Gauges go to 1 when the feature is enabled, 0 when
// it is not — dashboards can show degraded state on partially-supported
// kernels at a glance. Calling repeatedly with the same name updates the
// existing gauge rather than registering a duplicate.
//
// Caveat: the gauge is process-global while the capability state it reports
// is per-socket. With multiple listen routines the last probe wins, and a
// runtime downgrade on one socket (e.g. the GSO EIO disable) flips the gauge
// for all of them. Treat it as "at least one socket looks like this."
func recordCapability(name string, enabled bool) {
	g := metrics.GetOrRegisterGauge(name, nil)
	if enabled {
		g.Update(1)
	} else {
		g.Update(0)
	}
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return true
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) SetSoMark(mark int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_MARK, mark)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *StdConn) GetSoMark() (int, error) {
	return unix.GetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_MARK)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported sock type: %T", sa)
	}
}

// recvmmsg does one blocking recvmmsg (MSG_WAITFORONE), reading up to len(msgs) datagrams.
func (u *StdConn) recvmmsg(msgs []rawMessage) (int, error) {
	r, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(u.sysFd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		unix.MSG_WAITFORONE,
		0,
		0,
	)
	if errno != 0 {
		if u.closed.Load() {
			return 0, net.ErrClosed
		}
		return 0, &net.OpError{Op: "recvmmsg", Err: errno}
	}
	n := int(r)
	if (n == 0 || msgs[0].Len == 0) && u.closed.Load() {
		return 0, net.ErrClosed
	}
	return n, nil
}

// prepareRawMessages allocates the recvmmsg scratch:
// n rawMessages, each wired to its own bufSize receive buffer, sockaddr name slot
// and, when cmsgSpace > 0, a slice of one contiguous ancillary-data slab.
// All iovecs share a single slab kept alive by the msghdrs that point into it.
func prepareRawMessages(n, bufSize, cmsgSpace int) ([]rawMessage, [][]byte, [][]byte, []byte) {
	msgs := make([]rawMessage, n)
	buffers := make([][]byte, n)
	names := make([][]byte, n)
	iovs := make([]iovec, n)

	var cmsgs []byte
	if cmsgSpace > 0 {
		cmsgs = make([]byte, n*cmsgSpace)
	}

	for i := range msgs {
		buffers[i] = make([]byte, bufSize)
		names[i] = make([]byte, unix.SizeofSockaddrInet6)

		iovs[i].Base = &buffers[i][0]
		setIovLen(&iovs[i], bufSize)
		msgs[i].Hdr.Iov = &iovs[i]
		setMsgIovlen(&msgs[i].Hdr, 1)

		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(len(names[i]))

		if cmsgSpace > 0 {
			msgs[i].Hdr.Control = &cmsgs[i*cmsgSpace]
			setMsgControllen(&msgs[i].Hdr, cmsgSpace)
		}
	}

	return msgs, buffers, names, cmsgs
}

func getFrom(names [][]byte, i int, isV4 bool) netip.AddrPort {
	var ip netip.Addr
	// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
	if isV4 {
		ip, _ = netip.AddrFromSlice(names[i][4:8])
	} else {
		ip, _ = netip.AddrFromSlice(names[i][8:24])
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))
}

func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	bufSize := MTU
	cmsgSpace := 0
	if u.groSupported {
		bufSize = udpGROBufferSize
		cmsgSpace = unix.CmsgSpace(udpGROCmsgPayload)
	}
	msgs, buffers, names, _ := prepareRawMessages(u.batch, bufSize, cmsgSpace)

	for {
		if cmsgSpace > 0 {
			for i := range msgs {
				setMsgControllen(&msgs[i].Hdr, cmsgSpace)
			}
		}

		n, err := u.recvmmsg(msgs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue // interrupted by a signal, retry the read
			}
			// net.ErrClosed after Close() is teardown, absorbed by the caller's
			// closed flag like the other platforms; anything else is a real error.
			return err
		}

		for i := range n {
			from := getFrom(names, i, u.isV4)
			payload := buffers[i][:msgs[i].Len]

			segSize := 0
			if cmsgSpace > 0 {
				segSize = parseRecvCmsg(&msgs[i].Hdr)
			}

			deliverSegments(r, from, payload, segSize)
		}

		flush()
	}
}

// deliverSegments hands a received superdatagram to r, splitting it back into pre-coalesce packets
func deliverSegments(r EncReader, from netip.AddrPort, payload []byte, segSize int) {
	if segSize <= 0 || segSize >= len(payload) { //avoid bogus values
		r(from, payload[:len(payload):len(payload)])
		return
	}
	for off := 0; off < len(payload); off += segSize {
		end := off + segSize
		if end > len(payload) {
			end = len(payload)
		}
		r(from, payload[off:end:end])
	}
}

// parseRecvCmsg walks the per-slot ancillary buffer and extracts the UDP_GRO
// gso_size, or 0 when no UDP_GRO cmsg is present.
func parseRecvCmsg(hdr *msghdr) (gso int) {
	controllen := int(hdr.Controllen)
	if controllen < unix.SizeofCmsghdr || hdr.Control == nil {
		return 0
	}
	ctrl := unsafe.Slice(hdr.Control, controllen)
	off := 0
	for off+unix.SizeofCmsghdr <= len(ctrl) {
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&ctrl[off]))
		clen := int(ch.Len)
		// Compare against the remaining bytes rather than off+clen
		if clen < unix.SizeofCmsghdr || clen > len(ctrl)-off {
			return gso
		}
		dataOff := off + unix.CmsgLen(0)
		if ch.Level == unix.SOL_UDP && ch.Type == unix.UDP_GRO {
			if dataOff+udpGROCmsgPayload <= len(ctrl) {
				gso = int(int32(binary.NativeEndian.Uint32(ctrl[dataOff : dataOff+udpGROCmsgPayload])))
			}
		}
		// Advance by the aligned cmsg space.
		off += unix.CmsgSpace(clen - unix.CmsgLen(0))
	}
	return gso
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	return sendto(u.sysFd, b, ip, u.isV4)
}

func sendto(fd int, b []byte, addr netip.AddrPort, isV4 bool) error {
	var rsa [unix.SizeofSockaddrInet6]byte
	nlen, err := writeSockaddr(rsa[:], addr, isV4)
	if err != nil {
		return err
	}
	var base *byte
	if len(b) > 0 {
		base = &b[0]
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(fd),
		uintptr(unsafe.Pointer(base)),
		uintptr(len(b)),
		0,
		uintptr(unsafe.Pointer(&rsa[0])),
		uintptr(nlen),
	)
	if errno != 0 {
		return &net.OpError{Op: "sendto", Err: errno}
	}
	return nil
}

// WriteBatch sends bufs via sendmmsg(2), coalescing same-destination runs into UDP-GSO superpackets when supported.
// See batchWriter in udp_linux_writebatch.go for the mechanics.
func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	return u.bw.WriteBatch(bufs, addrs)
}

// writeSockaddr encodes addr into buf (which must be at least SizeofSockaddrInet6 bytes).
// Returns the number of bytes used.
// If isV4 is true and addr is not a v4 (or v4-in-v6) address, returns an error.
func writeSockaddr(buf []byte, addr netip.AddrPort, isV4 bool) (int, error) {
	ap := addr.Addr().Unmap()
	if isV4 {
		if !ap.Is4() {
			return 0, ErrInvalidIPv6RemoteForSocket
		}
		// struct sockaddr_in: { sa_family_t(2), in_port_t(2, BE), in_addr(4), zero(8) }
		// sa_family is host endian.
		binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], addr.Port())
		ip4 := ap.As4()
		copy(buf[4:8], ip4[:])
		for j := 8; j < 16; j++ {
			buf[j] = 0
		}
		return unix.SizeofSockaddrInet4, nil
	}
	// struct sockaddr_in6: { sa_family_t(2), in_port_t(2, BE), flowinfo(4), in6_addr(16), scope_id(4) }
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], addr.Port())
	binary.NativeEndian.PutUint32(buf[4:8], 0)
	ip6 := addr.Addr().As16()
	copy(buf[8:24], ip6[:])
	binary.NativeEndian.PutUint32(buf[24:28], 0)
	return unix.SizeofSockaddrInet6, nil
}

func (u *StdConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		if err := u.SetRecvBuffer(b); err == nil {
			if s, err := u.GetRecvBuffer(); err == nil {
				u.l.Info("listen.read_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.read_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.read_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		if err := u.SetSendBuffer(b); err == nil {
			if s, err := u.GetSendBuffer(); err == nil {
				u.l.Info("listen.write_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.write_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.write_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		if err := u.SetSoMark(b); err == nil {
			if s, err := u.GetSoMark(); err == nil {
				u.l.Info("listen.so_mark was set", "mark", s)
			} else {
				u.l.Warn("Failed to get listen.so_mark", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.so_mark", "error", err)
		}
	}
}

func (u *StdConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func (u *StdConn) Close() error {
	u.closed.Store(true)
	// Wake the reader parked in recvmmsg. shutdown(2) on an unconnected socket
	// returns ENOTCONN but still wakes it, so ignore the error.
	// The reader then sees closed and stops touching the fd, making the Close below safe.
	_ = unix.Shutdown(u.sysFd, unix.SHUT_RDWR)
	return unix.Close(u.sysFd)
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var udpGauges [][unix.SK_MEMINFO_VARS]metrics.Gauge
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	if err := udpConns[0].(*StdConn).getMemInfo(&meminfo); err == nil {
		udpGauges = make([][unix.SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
		for i := range udpConns {
			udpGauges[i] = [unix.SK_MEMINFO_VARS]metrics.Gauge{
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rcvbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.sndbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.fwd_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_queued", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.optmem", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.backlog", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.drops", i), nil),
			}
		}
	}

	return func() {
		for i, gauges := range udpGauges {
			if err := udpConns[i].(*StdConn).getMemInfo(&meminfo); err == nil {
				for j := 0; j < unix.SK_MEMINFO_VARS; j++ {
					gauges[j].Update(int64(meminfo[j]))
				}
			}
		}
	}
}
