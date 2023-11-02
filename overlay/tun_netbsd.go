//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

type ifreqDestroy struct {
	Name [16]byte
	pad  [16]byte
}

type tun struct {
	Device    string
	cidr      *net.IPNet
	MTU       int
	Routes    []Route
	routeTree *cidr.Tree4[iputil.VpnIp]
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

		err = ioctl(uintptr(s), syscall.SIOCIFDESTROY, uintptr(unsafe.Pointer(&ifreq)))

		return err
	}
	return nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in NetBSD")
}

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool, _ bool) (*tun, error) {
	// Try to open tun device
	var file *os.File
	var err error
	if deviceName == "" {
		return nil, fmt.Errorf("a device name in the format of /dev/tunN must be specified")
	}
	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("a device name in the format of /dev/tunN must be specified")
	}
	file, err = os.OpenFile("/dev/"+deviceName, os.O_RDWR, 0)

	if err != nil {
		return nil, err
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
	cmd := exec.Command("/sbin/ifconfig", t.Device, t.cidr.String(), t.cidr.IP.String())
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	cmd = exec.Command("/sbin/route", "-n", "add", "-net", t.cidr.String(), t.cidr.IP.String())
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}

	cmd = exec.Command("/sbin/ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU))
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}
	// Unsafe path routes
	for _, r := range t.Routes {
		if r.Via == nil || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		cmd = exec.Command("/sbin/route", "-n", "add", "-net", r.Cidr.String(), t.cidr.IP.String())
		t.l.Debug("command: ", cmd.String())
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("failed to run 'route add' for unsafe_route %s: %s", r.Cidr.String(), err)
		}
	}

	return nil
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	_, r := t.routeTree.MostSpecificContains(ip)
	return r
}

func (t *tun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for netbsd")
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}
