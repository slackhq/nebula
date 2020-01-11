package nebula

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Tun struct {
	io.ReadWriteCloser
	Device       string
	Cidr         *net.IPNet
	DefaultMTU   int
	TXQueueLen   int
	UnsafeRoutes []route
}

type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}

var sockaddrCtlSize uintptr = 32

const (
	_SYSPROTO_CONTROL = 2              //define SYSPROTO_CONTROL 2 /* kernel control protocol */
	_AF_SYS_CONTROL   = 2              //#define AF_SYS_CONTROL 2 /* corresponding sub address type */
	_PF_SYSTEM        = unix.AF_SYSTEM //#define PF_SYSTEM AF_SYSTEM
	_CTLIOCGINFO      = 3227799043     //#define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)
	utunControlName   = "com.apple.net.utun_control"
)

type ifreqAddr struct {
	Name [16]byte
	Addr unix.RawSockaddrInet4
	pad  [8]byte
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

func newTun(name string, cidr *net.IPNet, defaultMTU int, routes []route, unsafeRoutes []route, txQueueLen int) (tun *Tun, err error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("Route MTU not supported in Darwin")
	}
  	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]* on Darwin")
		}
	}
	fd, err := unix.Socket(_PF_SYSTEM, unix.SOCK_DGRAM, _SYSPROTO_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("system socket: %v", err)
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], []byte(utunControlName))

	err = ioctl(uintptr(fd), uintptr(_CTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo)))
	if err != nil {
		return nil, fmt.Errorf("CTLIOCGINFO: %v", err)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: _AF_SYS_CONTROL,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	scPointer := unsafe.Pointer(&sc)

	_, _, errno := unix.RawSyscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(scPointer),
		uintptr(sockaddrCtlSize),
	)
	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, fmt.Errorf("SetNonblock: %v", err)
	}

	file := os.NewFile(uintptr(fd), "")

	tun = &Tun{
		ReadWriteCloser: file,
		Device:          name,
		Cidr:            cidr,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		UnsafeRoutes:    unsafeRoutes,
	}

	return tun, nil
}

func (t *Tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}

func (t *Tun) Activate() error {
	devName := t.deviceBytes()

	var addr, mask [4]byte

	copy(addr[:], t.Cidr.IP.To4())
	copy(mask[:], t.Cidr.Mask)

	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}

	fd := uintptr(s)

	ifra := ifreqAddr{
		Name: devName,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   addr,
		},
	}

	// Set the device ip address
	if err = ioctl(fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun address: %s", err)
	}

	// Set the device network
	ifra.Addr.Addr = mask
	if err = ioctl(fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun netmask: %s", err)
	}

	// Set the device name
	ifrf := ifReq{Name: devName}
	if err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set tun device name: %s", err)
	}

	// Set the MTU on the device
	ifm := ifreqMTU{Name: devName, MTU: int32(t.DefaultMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		return fmt.Errorf("Failed to set tun mtu: %v", err)
	}

	/*
		// Set the transmit queue length
		ifrq := ifreqQLEN{Name: devName, Value: int32(t.TXQueueLen)}
		if err = ioctl(fd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
			// If we can't set the queue length nebula will still work but it may lead to packet loss
			l.WithError(err).Error("Failed to set tun tx queue length")
		}
	*/

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	if err = exec.Command("route", "-n", "add", "-net", t.Cidr.String(), "-interface", t.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}
	// Unsafe path routes
	for _, r := range c.UnsafeRoutes {
		if err = exec.Command("route", "-n", "add", "-net", r.route.String(), "-interface", c.Device).Run(); err != nil {
			return fmt.Errorf("failed to run 'route add' for unsafe_route %s: %s", r.route.String(), err)
		}
	}

	return nil
}

func (t *Tun) WriteRaw(b []byte) error {
	var nn int

	// add packet information header
	var h [4]byte
	h[0] = 0x00
	h[1] = 0x00
	h[2] = 0x00
	h[3] = unix.AF_INET
	b = append(h[:], b[:]...)

	for {
		max := len(b)
		n, err := t.ReadWriteCloser.Write(b[nn:max])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return err
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
}

var _ io.ReadWriteCloser = (*Tun)(nil)

func (t *Tun) Read(to []byte) (int, error) {

	buf := make([]byte, len(to)+4)

	n, err := t.ReadWriteCloser.Read(buf)

	copy(to, buf[4:])
	return n - 4, err
}

func (t *Tun) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	buf := make([]byte, len(from)+4)

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		buf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		buf[3] = syscall.AF_INET6
	} else {
		return 0, fmt.Errorf("Unable to determine IP version from packet")
	}

	copy(buf[4:], from)

	n, err := t.ReadWriteCloser.Write(buf)
	return n - 4, err
}
