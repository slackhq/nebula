//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn/winrio"
)

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

type Conn struct {
	l       *logrus.Logger
	sock    windows.Handle
	rx, tx  ringBuffer
	rq      winrio.Rq
	results [packetsPerRing]winrio.Result
}

func NewUDPStatsEmitter(_ []*Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func NewListener(l *logrus.Logger, ip string, port int, multi bool, batch int) (*Conn, error) {
	if !winrio.Initialize() {
		return nil, errors.New("doh, winrio bad")
	}

	c := &Conn{l: l}

	//TODO: respect the listen address, ipv6 listen blows up if you give it a v4
	//addr := [16]byte{}
	//copy(addr[:], net.ParseIP(ip).To16())
	//err := c.bind(&windows.SockaddrInet6{Addr: addr, Port: port})
	err := c.bind(&windows.SockaddrInet6{Port: port})
	if err != nil {
		return nil, err
	}

	for i := 0; i < packetsPerRing; i++ {
		err = c.insertReceiveRequest()
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Conn) bind(sa windows.Sockaddr) error {
	//net.ListenPacket()
	var err error
	c.sock, err = winrio.Socket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		return err
	}

	syscall.SetsockoptInt(syscall.Handle(c.sock), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)

	err = c.rx.Open()
	if err != nil {
		return err
	}

	err = c.tx.Open()
	if err != nil {
		return err
	}

	c.rq, err = winrio.CreateRequestQueue(c.sock, packetsPerRing, 1, packetsPerRing, 1, c.rx.cq, c.tx.cq, 0)
	if err != nil {
		return err
	}

	err = windows.Bind(c.sock, sa)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	udpAddr := &Addr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := c.receive(buffer)
		if err != nil {
			c.l.WithError(err).Error("Failed to read packets")
			continue
		}

		//c.l.WithField("rua", rua).Error("nate")

		udpAddr.IP = rua.Addr[:]
		p := (*[2]byte)(unsafe.Pointer(&udpAddr.Port))
		p[0] = byte(rua.Port >> 8)
		p[1] = byte(rua.Port)
		r(udpAddr, plaintext[:0], buffer[:n], h, fwPacket, lhf, nb, q, cache.Get(c.l))
	}
}

func (c *Conn) insertReceiveRequest() error {
	packet := c.rx.Push()
	dataBuffer := &winrio.Buffer{
		Id:     c.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - c.rx.packets),
		Length: uint32(len(packet.data)),
	}
	addressBuffer := &winrio.Buffer{
		Id:     c.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - c.rx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}

	return winrio.ReceiveEx(c.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, uintptr(unsafe.Pointer(packet)))
}

func (c *Conn) receive(buf []byte) (int, windows.RawSockaddrInet6, error) {
	c.rx.mu.Lock()
	defer c.rx.mu.Unlock()

	var err error
	var count uint32
	var results [1]winrio.Result
retry:
	count = 0
	for tries := 0; count == 0 && tries < receiveSpins; tries++ {
		if tries > 0 {
			procyield(1)
		}
		count = winrio.DequeueCompletion(c.rx.cq, results[:])
	}
	if count == 0 {
		err = winrio.Notify(c.rx.cq)
		if err != nil {
			return 0, windows.RawSockaddrInet6{}, err
		}
		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(c.rx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return 0, windows.RawSockaddrInet6{}, err
		}

		count = winrio.DequeueCompletion(c.rx.cq, results[:])
		if count == 0 {
			return 0, windows.RawSockaddrInet6{}, io.ErrNoProgress

		}
	}
	c.rx.Return(1)
	err = c.insertReceiveRequest()
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
	//TODO: you really don't need to return ep dumbass
	return n, ep, nil
}

func (c *Conn) WriteTo(buf []byte, nend *Addr) error {
	if len(buf) > bytesPerPacket {
		return io.ErrShortBuffer
	}
	c.tx.mu.Lock()
	defer c.tx.mu.Unlock()
	count := winrio.DequeueCompletion(c.tx.cq, c.results[:])
	if count == 0 && c.tx.isFull {
		err := winrio.Notify(c.tx.cq)
		if err != nil {
			return err
		}
		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(c.tx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return err
		}
		count = winrio.DequeueCompletion(c.tx.cq, c.results[:])
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	if count > 0 {
		c.tx.Return(count)
	}
	packet := c.tx.Push()

	packet.addr.Family = windows.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&packet.addr.Port))
	p[0] = byte(nend.Port >> 8)
	p[1] = byte(nend.Port)
	copy(packet.addr.Addr[:], nend.IP.To16())
	copy(packet.data[:], buf)

	dataBuffer := &winrio.Buffer{
		Id:     c.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - c.tx.packets),
		Length: uint32(len(buf)),
	}
	addressBuffer := &winrio.Buffer{
		Id:     c.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - c.tx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}

	return winrio.SendEx(c.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, 0)
}

func (c *Conn) LocalAddr() (*Addr, error) {
	sa, err := windows.Getsockname(c.sock)
	if err != nil {
		return nil, err
	}

	v6 := sa.(*windows.SockaddrInet6)
	return &Addr{
		IP:   v6.Addr[:],
		Port: uint16(v6.Port),
	}, nil
}

func (c *Conn) Rebind() error {
	return nil
}

func (c *Conn) ReloadConfig(*config.C) {}

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

type afWinRingBind struct {
	sock      windows.Handle
	rx, tx    ringBuffer
	rq        winrio.Rq
	mu        sync.Mutex
	blackhole bool
}

// WinRingBind uses Windows registered I/O for fast ring buffered networking.
type WinRingBind struct {
	v4, v6 afWinRingBind
	mu     sync.RWMutex
	isOpen uint32
}

func (bind *afWinRingBind) CloseAndZero() {
	bind.rx.CloseAndZero()
	bind.tx.CloseAndZero()
	if bind.sock != 0 {
		windows.CloseHandle(bind.sock)
		bind.sock = 0
	}
	bind.blackhole = false
}

func (bind *WinRingBind) closeAndZero() {
	atomic.StoreUint32(&bind.isOpen, 0)
	bind.v4.CloseAndZero()
	bind.v6.CloseAndZero()
}

func (bind *WinRingBind) Close() error {
	bind.mu.RLock()
	if atomic.LoadUint32(&bind.isOpen) != 1 {
		bind.mu.RUnlock()
		return nil
	}
	atomic.StoreUint32(&bind.isOpen, 2)
	windows.PostQueuedCompletionStatus(bind.v4.rx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v4.tx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v6.rx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v6.tx.iocp, 0, 0, nil)
	bind.mu.RUnlock()
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.closeAndZero()
	return nil
}

//TODO: Revert all changes to wintun and try again
