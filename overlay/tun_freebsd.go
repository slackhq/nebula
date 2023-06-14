//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

const (
	FIODGNAME = 0x80106678
)

type fiodgnameArg struct {
	length int32
	pad    [4]byte
	buf    unsafe.Pointer
}

type ifreqRename struct {
	Name [16]byte
	Data uintptr
}

type ifreqDestroy struct {
	Name [16]byte
	pad  [16]byte
}

type tun struct {
	Device    string
	cidr      *net.IPNet
	MTU       int
	Routes    []Route
	routeTree *cidr.Tree4
	l         *logrus.Logger

	io.ReadWriteCloser
}

func (t *tun) Close() error {
	if t.ReadWriteCloser != nil {
		if err := t.ReadWriteCloser.Close(); err != nil {
			return err
		}

		s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
		if err != nil {
			return err
		}
		defer syscall.Close(s)

		ifreq := ifreqDestroy{Name: t.deviceBytes()}

		// Destroy the interface
		err = ioctl(uintptr(s), syscall.SIOCIFDESTROY, uintptr(unsafe.Pointer(&ifreq)))
		return err
	}

	return nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in FreeBSD")
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool, _ bool) (*tun, error) {
	// Try to open existing tun device
	var file *os.File
	var err error
	if deviceName != "" {
		file, err = os.OpenFile("/dev/"+deviceName, os.O_RDWR, 0)
	}
	if errors.Is(err, fs.ErrNotExist) || deviceName == "" {
		// If the device doesn't already exist, request a new one and rename it
		file, err = os.OpenFile("/dev/tun", os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}

	rawConn, err := file.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("SyscallConn: %v", err)
	}

	var name [16]byte
	var ctrlErr error
	rawConn.Control(func(fd uintptr) {
		arg := fiodgnameArg{length: 16, buf: unsafe.Pointer(&name)}
		ctrlErr = ioctl(fd, FIODGNAME, uintptr(unsafe.Pointer(&arg)))
	})
	if ctrlErr != nil {
		return nil, err
	}

	ifName := string(bytes.TrimRight(name[:], "\x00"))
	if deviceName == "" {
		deviceName = ifName
	}

	if ifName != deviceName {
		s, err := syscall.Socket(
			syscall.AF_INET,
			syscall.SOCK_DGRAM,
			syscall.IPPROTO_IP,
		)
		if err != nil {
			return nil, err
		}
		defer syscall.Close(s)

		fd := uintptr(s)

		var fromName [16]byte
		var toName [16]byte
		copy(fromName[:], ifName)
		copy(toName[:], deviceName)

		ifrr := ifreqRename{
			Name: fromName,
			Data: uintptr(unsafe.Pointer(&toName)),
		}

		// Set the device name
		ioctl(fd, syscall.SIOCSIFNAME, uintptr(unsafe.Pointer(&ifrr)))
	}

	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	return &tun{
		ReadWriteCloser: file,
		Device:          deviceName,
		cidr:            cidr,
		MTU:             defaultMTU,
		Routes:          routes,
		routeTree:       routeTree,
		l:               l,
	}, nil
}

func (t *tun) Activate() error {
	var err error
	// TODO use syscalls instead of exec.Command
	t.l.Debug("command: ifconfig", t.Device, t.cidr.String(), t.cidr.IP.String())
	if err = exec.Command("/sbin/ifconfig", t.Device, t.cidr.String(), t.cidr.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	t.l.Debug("command: route", "-n", "add", "-net", t.cidr.String(), "-interface", t.Device)
	if err = exec.Command("/sbin/route", "-n", "add", "-net", t.cidr.String(), "-interface", t.Device).Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}
	t.l.Debug("command: ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU))
	if err = exec.Command("/sbin/ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	// Unsafe path routes
	for _, r := range t.Routes {
		if r.Via == nil || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		t.l.Debug("command: route", "-n", "add", "-net", r.Cidr.String(), "-interface", t.Device)
		if err = exec.Command("/sbin/route", "-n", "add", "-net", r.Cidr.String(), "-interface", t.Device).Run(); err != nil {
			return fmt.Errorf("failed to run 'route add' for unsafe_route %s: %s", r.Cidr.String(), err)
		}
	}

	return nil
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for freebsd")
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}
