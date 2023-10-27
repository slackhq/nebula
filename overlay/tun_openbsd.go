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

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

type tun struct {
	Device    string
	cidr      *net.IPNet
	MTU       int
	Routes    []Route
	routeTree *cidr.Tree4
	l         *logrus.Logger

	io.ReadWriteCloser

	// cache out buffer since we need to prepend 4 bytes for tun metadata
	out []byte
}

func (t *tun) Close() error {
	if t.ReadWriteCloser != nil {
		return t.ReadWriteCloser.Close()
	}

	return nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in OpenBSD")
}

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool, _ bool) (*tun, error) {
	if deviceName == "" {
		return nil, fmt.Errorf("a device name in the format of tunN must be specified")
	}

	if !deviceNameRE.MatchString(deviceName) {
		return nil, fmt.Errorf("a device name in the format of tunN must be specified")
	}

	file, err := os.OpenFile("/dev/"+deviceName, os.O_RDWR, 0)
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

	cmd = exec.Command("/sbin/ifconfig", t.Device, "mtu", strconv.Itoa(t.MTU))
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	cmd = exec.Command("/sbin/route", "-n", "add", "-inet", t.cidr.String(), t.cidr.IP.String())
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'route add': %s", err)
	}

	// Unsafe path routes
	for _, r := range t.Routes {
		if r.Via == nil || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		cmd = exec.Command("/sbin/route", "-n", "add", "-inet", r.Cidr.String(), t.cidr.IP.String())
		t.l.Debug("command: ", cmd.String())
		if err = cmd.Run(); err != nil {
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

func (t *tun) Read(to []byte) (int, error) {
	buf := make([]byte, len(to)+4)

	n, err := t.ReadWriteCloser.Read(buf)

	copy(to, buf[4:])
	return n - 4, err
}

// Write is only valid for single threaded use
func (t *tun) Write(from []byte) (int, error) {
	buf := t.out
	if cap(buf) < len(from)+4 {
		buf = make([]byte, len(from)+4)
		t.out = buf
	}
	buf = buf[:len(from)+4]

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		buf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		buf[3] = syscall.AF_INET6
	} else {
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}

	copy(buf[4:], from)

	n, err := t.ReadWriteCloser.Write(buf)
	return n - 4, err
}
