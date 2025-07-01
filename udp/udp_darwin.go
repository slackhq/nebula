//go:build !e2e_testing
// +build !e2e_testing

package udp

// Darwin support is primarily implemented in udp_generic, besides NewListenConfig

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	*net.UDPConn
	isV4  bool
	sysFd uintptr
	l     *logrus.Logger
}

var _ Conn = &StdConn{}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", net.JoinHostPort(ip.String(), fmt.Sprintf("%v", port)))
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
			return fmt.Errorf("listener is IPv4, but writing to IPv6 remote")
		}

		var rsa unix.RawSockaddrInet6
		rsa.Family = unix.AF_INET6
		rsa.Addr = ap.Addr().As16()
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

	writeErrors := 0
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
			// Try to suss out whether this is a transient error or something more permanent
			writeErrors++
			u.l.WithError(err).WithField("consecutiveErrors", writeErrors).Error("unexpected udp socket write error")

			if writeErrors > 15 {
				panic("too many consecutive UDP write errors")

			} else if writeErrors > 10 {
				time.Sleep(100 * time.Millisecond)
			}

			continue
		}

		if errors.Is(err, syscall.EBADF) {
			return net.ErrClosed
		}

		return &net.OpError{Op: "sendto", Err: err}
	}
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

func (u *StdConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		r(
			netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()),
			plaintext[:0],
			buffer[:n],
			h,
			fwPacket,
			lhf,
			nb,
			q,
			cache.Get(u.l),
		)
	}
}

func (u *StdConn) Rebind() error {
	var err error
	if u.isV4 {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, 0)
	} else {
		err = syscall.SetsockoptInt(int(u.sysFd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, 0)
	}

	if err != nil {
		u.l.WithError(err).Error("Failed to rebind udp socket")
	}

	return nil
}
