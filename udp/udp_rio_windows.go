//go:build !e2e_testing
// +build !e2e_testing

// Inspired by https://git.zx2c4.com/wireguard-go/tree/conn/bind_windows.go

package udp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn/winrio"
)

// Assert we meet the standard conn interface
var _ Conn = &RIOConn{}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

const (
	packetsPerRing = 1024
	bytesPerPacket = 2048 - 32
	receiveSpins   = 15
)

type ringPacket struct {
	addr windows.RawSockaddrInet6
	data [bytesPerPacket]byte
}

type ringBuffer struct {
	packets    uintptr
	head, tail uint32
	id         winrio.BufferId
	iocp       windows.Handle
	isFull     bool
	cq         winrio.Cq
	mu         sync.Mutex
	overlapped windows.Overlapped
}

type RIOConn struct {
	isOpen  atomic.Bool
	l       *logrus.Logger
	sock    windows.Handle
	rx, tx  ringBuffer
	rq      winrio.Rq
	results [packetsPerRing]winrio.Result
}

func NewRIOListener(l *logrus.Logger, addr netip.Addr, port int) (*RIOConn, error) {
	if !winrio.Initialize() {
		return nil, errors.New("could not initialize winrio")
	}

	u := &RIOConn{l: l}

	err := u.bind(l, &windows.SockaddrInet6{Addr: addr.As16(), Port: port})
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	for i := 0; i < packetsPerRing; i++ {
		err = u.insertReceiveRequest()
		if err != nil {
			return nil, fmt.Errorf("init rx ring: %w", err)
		}
	}

	u.isOpen.Store(true)
	return u, nil
}

func (u *RIOConn) bind(l *logrus.Logger, sa windows.Sockaddr) error {
	var err error
	u.sock, err = winrio.Socket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("winrio.Socket error: %w", err)
	}

	// Enable v4 for this socket
	syscall.SetsockoptInt(syscall.Handle(u.sock), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)

	// Disable reporting of PORT_UNREACHABLE and NET_UNREACHABLE errors from the UDP socket receive call.
	// These errors are returned on Windows during UDP receives based on the receipt of ICMP packets. Disable
	// the UDP receive error returns with these ioctl calls.
	ret := uint32(0)
	flag := uint32(0)
	size := uint32(unsafe.Sizeof(flag))
	err = syscall.WSAIoctl(syscall.Handle(u.sock), syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &ret, nil, 0)
	if err != nil {
		// This is a best-effort to prevent errors from being returned by the udp recv operation.
		// Quietly log a failure and continue.
		l.WithError(err).Debug("failed to set UDP_CONNRESET ioctl")
	}

	ret = 0
	flag = 0
	size = uint32(unsafe.Sizeof(flag))
	SIO_UDP_NETRESET := uint32(syscall.IOC_IN | syscall.IOC_VENDOR | 15)
	err = syscall.WSAIoctl(syscall.Handle(u.sock), SIO_UDP_NETRESET, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &ret, nil, 0)
	if err != nil {
		// This is a best-effort to prevent errors from being returned by the udp recv operation.
		// Quietly log a failure and continue.
		l.WithError(err).Debug("failed to set UDP_NETRESET ioctl")
	}

	err = u.rx.Open()
	if err != nil {
		return fmt.Errorf("error rx.Open(): %w", err)
	}

	err = u.tx.Open()
	if err != nil {
		return fmt.Errorf("error tx.Open(): %w", err)
	}

	u.rq, err = winrio.CreateRequestQueue(u.sock, packetsPerRing, 1, packetsPerRing, 1, u.rx.cq, u.tx.cq, 0)
	if err != nil {
		return fmt.Errorf("error CreateRequestQueue: %w", err)
	}

	err = windows.Bind(u.sock, sa)
	if err != nil {
		return fmt.Errorf("error windows.Bind(): %w", err)
	}

	return nil
}

func (u *RIOConn) ListenOut(r EncReader) {
	buffer := make([]byte, MTU)

	var lastRecvErr time.Time

	for {
		// Just read one packet at a time
		n, rua, err := u.receive(buffer)

		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
				return
			}
			// Dampen unexpected message warns to once per minute
			if lastRecvErr.IsZero() || time.Since(lastRecvErr) > time.Minute {
				lastRecvErr = time.Now()
				u.l.WithError(err).Warn("unexpected udp socket receive error")
			}
			continue
		}

		r(netip.AddrPortFrom(netip.AddrFrom16(rua.Addr).Unmap(), (rua.Port>>8)|((rua.Port&0xff)<<8)), buffer[:n])
	}
}

func (u *RIOConn) insertReceiveRequest() error {
	packet := u.rx.Push()
	dataBuffer := &winrio.Buffer{
		Id:     u.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - u.rx.packets),
		Length: uint32(len(packet.data)),
	}
	addressBuffer := &winrio.Buffer{
		Id:     u.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - u.rx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}

	return winrio.ReceiveEx(u.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, uintptr(unsafe.Pointer(packet)))
}

func (u *RIOConn) receive(buf []byte) (int, windows.RawSockaddrInet6, error) {
	if !u.isOpen.Load() {
		return 0, windows.RawSockaddrInet6{}, net.ErrClosed
	}

	u.rx.mu.Lock()
	defer u.rx.mu.Unlock()

	var err error
	var count uint32
	var results [1]winrio.Result

retry:
	count = 0
	for tries := 0; count == 0 && tries < receiveSpins; tries++ {
		if tries > 0 {
			if !u.isOpen.Load() {
				return 0, windows.RawSockaddrInet6{}, net.ErrClosed
			}
			procyield(1)
		}

		count = winrio.DequeueCompletion(u.rx.cq, results[:])
	}

	if count == 0 {
		err = winrio.Notify(u.rx.cq)
		if err != nil {
			return 0, windows.RawSockaddrInet6{}, err
		}
		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(u.rx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return 0, windows.RawSockaddrInet6{}, err
		}

		if !u.isOpen.Load() {
			return 0, windows.RawSockaddrInet6{}, net.ErrClosed
		}

		count = winrio.DequeueCompletion(u.rx.cq, results[:])
		if count == 0 {
			return 0, windows.RawSockaddrInet6{}, io.ErrNoProgress

		}
	}

	u.rx.Return(1)
	err = u.insertReceiveRequest()
	if err != nil {
		return 0, windows.RawSockaddrInet6{}, err
	}

	// We limit the MTU well below the 65k max for practicality, but this means a remote host can still send us
	// huge packets. Just try again when this happens. The infinite loop this could cause is still limited to
	// attacker bandwidth, just like the rest of the receive path.
	if windows.Errno(results[0].Status) == windows.WSAEMSGSIZE {
		goto retry
	}

	if results[0].Status != 0 {
		return 0, windows.RawSockaddrInet6{}, windows.Errno(results[0].Status)
	}

	packet := (*ringPacket)(unsafe.Pointer(uintptr(results[0].RequestContext)))
	ep := packet.addr
	n := copy(buf, packet.data[:results[0].BytesTransferred])
	return n, ep, nil
}

func (u *RIOConn) WriteTo(buf []byte, ip netip.AddrPort) error {
	if !u.isOpen.Load() {
		return net.ErrClosed
	}

	if len(buf) > bytesPerPacket {
		return io.ErrShortBuffer
	}

	u.tx.mu.Lock()
	defer u.tx.mu.Unlock()

	count := winrio.DequeueCompletion(u.tx.cq, u.results[:])
	if count == 0 && u.tx.isFull {
		err := winrio.Notify(u.tx.cq)
		if err != nil {
			return err
		}

		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(u.tx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return err
		}

		if !u.isOpen.Load() {
			return net.ErrClosed
		}

		count = winrio.DequeueCompletion(u.tx.cq, u.results[:])
		if count == 0 {
			return io.ErrNoProgress
		}
	}

	if count > 0 {
		u.tx.Return(count)
	}

	packet := u.tx.Push()
	packet.addr.Family = windows.AF_INET6
	packet.addr.Addr = ip.Addr().As16()
	port := ip.Port()
	packet.addr.Port = (port >> 8) | ((port & 0xff) << 8)
	copy(packet.data[:], buf)

	dataBuffer := &winrio.Buffer{
		Id:     u.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - u.tx.packets),
		Length: uint32(len(buf)),
	}

	addressBuffer := &winrio.Buffer{
		Id:     u.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - u.tx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}

	return winrio.SendEx(u.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, 0)
}

func (u *RIOConn) LocalAddr() (netip.AddrPort, error) {
	sa, err := windows.Getsockname(u.sock)
	if err != nil {
		return netip.AddrPort{}, err
	}

	v6 := sa.(*windows.SockaddrInet6)
	return netip.AddrPortFrom(netip.AddrFrom16(v6.Addr).Unmap(), uint16(v6.Port)), nil

}

func (u *RIOConn) SupportsMultipleReaders() bool {
	return false
}

func (u *RIOConn) Rebind() error {
	return nil
}

func (u *RIOConn) ReloadConfig(*config.C) {}

func (u *RIOConn) Close() error {
	if !u.isOpen.CompareAndSwap(true, false) {
		return nil
	}

	windows.PostQueuedCompletionStatus(u.rx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(u.tx.iocp, 0, 0, nil)

	u.rx.CloseAndZero()
	u.tx.CloseAndZero()
	if u.sock != 0 {
		windows.CloseHandle(u.sock)
	}
	return nil
}

func (ring *ringBuffer) Push() *ringPacket {
	for ring.isFull {
		panic("ring is full")
	}
	ret := (*ringPacket)(unsafe.Pointer(ring.packets + (uintptr(ring.tail%packetsPerRing) * unsafe.Sizeof(ringPacket{}))))
	ring.tail += 1
	if ring.tail%packetsPerRing == ring.head%packetsPerRing {
		ring.isFull = true
	}
	return ret
}

func (ring *ringBuffer) Return(count uint32) {
	if ring.head%packetsPerRing == ring.tail%packetsPerRing && !ring.isFull {
		return
	}
	ring.head += count
	ring.isFull = false
}

func (ring *ringBuffer) CloseAndZero() {
	if ring.cq != 0 {
		winrio.CloseCompletionQueue(ring.cq)
		ring.cq = 0
	}

	if ring.iocp != 0 {
		windows.CloseHandle(ring.iocp)
		ring.iocp = 0
	}

	if ring.id != 0 {
		winrio.DeregisterBuffer(ring.id)
		ring.id = 0
	}

	if ring.packets != 0 {
		windows.VirtualFree(ring.packets, 0, windows.MEM_RELEASE)
		ring.packets = 0
	}

	ring.head = 0
	ring.tail = 0
	ring.isFull = false
}

func (ring *ringBuffer) Open() error {
	var err error
	packetsLen := unsafe.Sizeof(ringPacket{}) * packetsPerRing
	ring.packets, err = windows.VirtualAlloc(0, packetsLen, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return err
	}

	ring.id, err = winrio.RegisterPointer(unsafe.Pointer(ring.packets), uint32(packetsLen))
	if err != nil {
		return err
	}

	ring.iocp, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
	if err != nil {
		return err
	}

	ring.cq, err = winrio.CreateIOCPCompletionQueue(packetsPerRing, ring.iocp, 0, &ring.overlapped)
	if err != nil {
		return err
	}

	return nil
}
