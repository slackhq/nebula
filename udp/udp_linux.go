//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	c     *net.UDPConn
	rc    syscall.RawConn
	isV4  bool
	l     *logrus.Logger
	batch int
}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if multi {
				var err error
				oErr := c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				})
				if oErr != nil {
					return fmt.Errorf("error while setting SO_REUSEPORT: %w", oErr)
				}
				if err != nil {
					return fmt.Errorf("unable to set SO_REUSEPORT: %w", err)
				}
			}

			return nil
		},
	}

	c, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("unable to open socket: %w", err)
	}

	uc := c.(*net.UDPConn)
	rc, err := uc.SyscallConn()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("unable to open sysfd: %w", err)
	}

	return &StdConn{c: uc, rc: rc, isV4: ip.Is4(), l: l, batch: batch}, err
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) SetRecvBuffer(n int) error {
	var err error
	oErr := u.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
	})
	if oErr != nil {
		return oErr
	}
	return err
}

func (u *StdConn) SetSendBuffer(n int) error {
	var err error
	oErr := u.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
	})
	if oErr != nil {
		return oErr
	}
	return err
}

func (u *StdConn) SetSoMark(mark int) error {
	var err error
	oErr := u.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
	})
	if oErr != nil {
		return oErr
	}
	return err
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	var err error
	var n int
	oErr := u.rc.Control(func(fd uintptr) {
		n, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	})
	if oErr != nil {
		return n, oErr
	}
	return n, err
}

func (u *StdConn) GetSendBuffer() (int, error) {
	var err error
	var n int
	oErr := u.rc.Control(func(fd uintptr) {
		n, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	if oErr != nil {
		return n, oErr
	}
	return n, err
}

func (u *StdConn) GetSoMark() (int, error) {
	var err error
	var n int
	oErr := u.rc.Control(func(fd uintptr) {
		n, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	})
	if oErr != nil {
		return n, oErr
	}
	return n, err
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	sa := u.c.LocalAddr()
	return netip.ParseAddrPort(sa.String())
}

func (u *StdConn) ListenOut(r EncReader) {
	var ip netip.Addr
	var n uintptr
	var err error
	msgs, buffers, names := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		read(msgs, &n, &err)
		if err != nil {
			u.l.WithError(err).Error("udp socket is closed, exiting read loop")
			return
		}

		for i := 0; i < int(n); i++ {
			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			//u.l.Error("GOT A PACKET", msgs[i].Len)
			r(netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4])), buffers[i][:msgs[i].Len])
		}
	}
}

func (u *StdConn) ReadSingle(msgs []rawMessage, n *uintptr, err *error) {
	oErr := u.rc.Read(func(fd uintptr) bool {
		in, _, nErr := unix.Syscall6(
			unix.SYS_RECVMSG,
			fd,
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			0, 0, 0, 0,
		)

		if nErr == syscall.EAGAIN || nErr == syscall.EINTR {
			// Retry read
			return false

		} else if nErr != 0 {
			u.l.Errorf("READING FROM UDP SINGLE had an errno %d", nErr)
			*err = &net.OpError{Op: "recvmsg", Err: nErr}
			*n = 0
			return true
		}

		msgs[0].Len = uint32(in)
		*n = 1
		return true
	})

	if *err == nil && oErr != nil {
		*err = oErr
		*n = 0
		return
	}
}

func (u *StdConn) ReadMulti(msgs []rawMessage, n *uintptr, err *error) {
	oErr := u.rc.Read(func(fd uintptr) bool {
		var nErr syscall.Errno
		*n, _, nErr = unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0, 0,
		)

		if nErr == syscall.EAGAIN || nErr == syscall.EINTR {
			// Retry read
			return false

		} else if nErr != 0 {
			u.l.Errorf("READING FROM UDP MULTI had an errno %d", nErr)
			*err = &net.OpError{Op: "recvmmsg", Err: nErr}
			*n = 0
			return true
		}

		return true
	})

	if *err == nil && oErr != nil {
		*err = oErr
		*n = 0
		return
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	_, err := u.c.WriteToUDPAddrPort(b, ip)
	return err
}

func (u *StdConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		err := u.SetSoMark(b)
		if err == nil {
			s, err := u.GetSoMark()
			if err == nil {
				u.l.WithField("mark", s).Info("listen.so_mark was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.so_mark")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.so_mark")
		}
	}
}

func (u *StdConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS
	var err error
	oErr := u.rc.Control(func(fd uintptr) {
		_, _, err = unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_SOCKET),
			uintptr(unix.SO_MEMINFO),
			uintptr(unsafe.Pointer(meminfo)),
			uintptr(unsafe.Pointer(&vallen)),
			0,
		)
	})
	if oErr != nil {
		return oErr
	}
	return err
}

func (u *StdConn) Close() error {
	err := u.c.Close()
	return err
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
