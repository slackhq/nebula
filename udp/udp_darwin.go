//go:build !e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	*net.UDPConn
	isV4  bool
	sysFd uintptr
	l     *slog.Logger
}

var _ Conn = &StdConn{}

func NewListener(l *slog.Logger, s Settings) (Conn, error) {
	lc := NewListenConfig(s.Multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", s.Listen.String())
	if err != nil {
		return nil, err
	}

	if uc, ok := pc.(*net.UDPConn); ok {
		c := &StdConn{UDPConn: uc, l: l}

		rc, err := uc.SyscallConn()
		if err != nil {
			return nil, fmt.Errorf("failed to open udp socket: %w", err)
		}

		err = rc.Control(func(fd uintptr) {
			c.sysFd = fd
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get udp fd: %w", err)
		}

		la, err := c.LocalAddr()
		if err != nil {
			return nil, err
		}
		c.isV4 = la.Addr().Is4()

		return c, nil
	}

	return nil, fmt.Errorf("unexpected PacketConn: %T %#v", pc, pc)
}

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				var controlErr error
				err := c.Control(func(fd uintptr) {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						controlErr = fmt.Errorf("SO_REUSEPORT failed: %v", err)
						return
					}
				})
				if err != nil {
					return err
				}
				if controlErr != nil {
					return controlErr
				}
			}

			return nil
		},
	}
}

//go:linkname sendto golang.org/x/sys/unix.sendto
//go:noescape
func sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen int32) (err error)

func (u *StdConn) WriteTo(b []byte, ap netip.AddrPort) error {
	var sa unsafe.Pointer
	var addrLen int32

	if u.isV4 {
		if ap.Addr().Is6() {
			return ErrInvalidIPv6RemoteForSocket
		}

		var rsa unix.RawSockaddrInet4
		rsa.Family = unix.AF_INET
		rsa.Addr = ap.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ap.Port())
		sa = unsafe.Pointer(&rsa)
		addrLen = syscall.SizeofSockaddrInet4
	} else {
		var rsa unix.RawSockaddrInet6
		rsa.Family = unix.AF_INET6
		rsa.Addr = ap.Addr().As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ap.Port())
		sa = unsafe.Pointer(&rsa)
		addrLen = syscall.SizeofSockaddrInet6
	}

	// Golang stdlib doesn't handle EAGAIN correctly in some situations so we do writes ourselves
	// See https://github.com/golang/go/issues/73919
	for {
		//_, _, err := unix.Syscall6(unix.SYS_SENDTO, u.sysFd, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, sa, addrLen)
		err := sendto(int(u.sysFd), b, 0, sa, addrLen)
		if err == nil {
			// Written, get out before the error handling
			return nil
		}

		if errors.Is(err, syscall.EINTR) {
			// Write was interrupted, retry
			continue
		}

		if errors.Is(err, syscall.EAGAIN) {
			return &net.OpError{Op: "sendto", Err: unix.EWOULDBLOCK}
		}

		if errors.Is(err, syscall.EBADF) {
			return net.ErrClosed
		}

		return &net.OpError{Op: "sendto", Err: err}
	}
}

func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	// An un-sendable destination costs its own packet, never the ones behind it in the batch.
	// TODO: WriteTo maps EWOULDBLOCK to an error, so a full send buffer
	// silently drops the rest of a burst (linux blocks instead). Poll for
	// writability on EAGAIN before giving up on the remainder.
	written := 0
	for i, b := range bufs {
		if err := u.WriteTo(b, addrs[i]); err == nil {
			written++
		} else {
			u.l.Debug("failed to write packet in batch", "udpAddr", addrs[i], "error", err)
		}
	}
	return written, nil
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *StdConn) ReloadConfig(c *config.C) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

// recvBatch is how many datagrams one recvmsg_x call may return.
const recvBatch = 64

// msghdrX mirrors xnu's struct msghdr_x (bsd/sys/socket_private.h). recvmsg_x reports each
// datagram's length in Datalen rather than in its return value.
// Keep in sync with msghdrX in overlay/tun_darwin.go.
type msghdrX struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

// ListenOut drains the socket with recvmsg_x, darwin's private batched recvmsg, so one syscall reads
// up to recvBatch datagrams instead of one. Sends stay on sendto: xnu batches sendmsg_x through
// the stack only on connected sockets, and on this unconnected one it loops sendit per message.
func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	rc, err := u.UDPConn.SyscallConn()
	if err != nil {
		return err
	}

	bufs := make([][]byte, recvBatch)
	names := make([]unix.RawSockaddrInet6, recvBatch)
	iovs := make([]unix.Iovec, recvBatch)
	hdrs := make([]msghdrX, recvBatch)
	for i := range hdrs {
		bufs[i] = make([]byte, MTU)
		iovs[i].Base = &bufs[i][0]
		iovs[i].SetLen(MTU)
		hdrs[i].Iov = &iovs[i]
		hdrs[i].Iovlen = 1
		hdrs[i].Name = (*byte)(unsafe.Pointer(&names[i]))
	}

	for {
		var n int
		var errno syscall.Errno
		err := rc.Read(func(fd uintptr) bool {
			for i := range hdrs {
				hdrs[i].Namelen = unix.SizeofSockaddrInet6
				hdrs[i].Flags = 0
				hdrs[i].Datalen = 0
			}
			r0, _, e := unix.Syscall6(unix.SYS_RECVMSG_X, fd, uintptr(unsafe.Pointer(&hdrs[0])), recvBatch, 0, 0, 0)
			if e == unix.EAGAIN {
				return false
			}
			n, errno = int(r0), e
			return true
		})
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			u.l.Error("unexpected udp socket receive error", "error", err)
			continue
		}
		if errno == unix.ENOSYS || errno == unix.EPERM || errno == unix.EOPNOTSUPP {
			// recvmsg_x is private, so a kernel or sandbox (such as an iOS extension's) may refuse it.
			u.l.Warn("recvmsg_x unavailable, reading one datagram per syscall", "error", errno)
			return u.listenOutSingle(r, flush)
		}
		if errno != 0 {
			if errno != unix.EINTR {
				u.l.Error("unexpected udp socket receive error", "error", errno)
			}
			continue
		}
		if err := checkMsghdrX(hdrs, names, n); err != nil {
			// The batch was read through a layout the kernel no longer writes, so none of it is trustworthy.
			u.l.Warn("recvmsg_x returned an unexpected header, reading one datagram per syscall", "error", err)
			return u.listenOutSingle(r, flush)
		}

		for i := 0; i < n; i++ {
			addr, ok := sockaddrToAddrPort(&names[i])
			if !ok {
				continue
			}
			l := int(hdrs[i].Datalen)
			r(addr, bufs[i][:l:l])
		}
		flush()
	}
}

// checkMsghdrX rejects a recvmsg_x result that intact msghdr_x entries can't produce, which is how a change
// to xnu's private struct layout would show up.
func checkMsghdrX(hdrs []msghdrX, names []unix.RawSockaddrInet6, n int) error {
	if n > len(hdrs) {
		return fmt.Errorf("returned %d datagrams for %d headers", n, len(hdrs))
	}
	for i := range n {
		if hdrs[i].Datalen > MTU {
			return fmt.Errorf("datagram %d is %d bytes, past the %d byte buffer", i, hdrs[i].Datalen, MTU)
		}
		switch {
		case names[i].Family == unix.AF_INET && hdrs[i].Namelen == unix.SizeofSockaddrInet4:
		case names[i].Family == unix.AF_INET6 && hdrs[i].Namelen == unix.SizeofSockaddrInet6:
		default:
			return fmt.Errorf("datagram %d has address family %d with length %d", i, names[i].Family, hdrs[i].Namelen)
		}
	}
	return nil
}

// listenOutSingle reads one datagram per recvfrom and flushes after each, for when recvmsg_x is refused or misbehaves.
func (u *StdConn) listenOutSingle(r EncReader, flush func()) error {
	buffer := make([]byte, MTU)

	for {
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			u.l.Error("unexpected udp socket receive error", "error", err)
			continue
		}

		r(netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()), buffer[:n:n])
		flush()
	}
}

func sockaddrToAddrPort(sa *unix.RawSockaddrInet6) (netip.AddrPort, bool) {
	switch sa.Family {
	case unix.AF_INET:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:])
		return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), port), true
	case unix.AF_INET6:
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), port), true
	}
	return netip.AddrPort{}, false
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return false
}

// Rebind clears the interface the kernel scoped this socket to, so that sends are routed against the current
// routing table instead of the interface we happened to be on when the socket was created. Darwin pins sockets
// this way on its own, which is what strands us after the underlying network changes.
func (u *StdConn) Rebind() error {
	var err error
	if u.isV4 {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, 0)
	} else {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, 0)
	}

	return err
}
