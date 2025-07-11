//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
)

type ifreqDestroy struct {
	Name [16]byte
	pad  [16]byte
}

type tun struct {
	Device      string
	vpnNetworks []netip.Prefix
	MTU         int
	Routes      atomic.Pointer[[]Route]
	routeTree   atomic.Pointer[bart.Table[routing.Gateways]]
	l           *logrus.Logger

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

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*tun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in NetBSD")
}

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*tun, error) {
	// Try to open tun device
	var file *os.File
	var err error
	deviceName := c.GetString("tun.dev", "")
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

	t := &tun{
		ReadWriteCloser: file,
		Device:          deviceName,
		vpnNetworks:     vpnNetworks,
		MTU:             c.GetInt("tun.mtu", DefaultMTU),
		l:               l,
	}

	err = t.reload(c, true)
	if err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := t.reload(c, false)
		if err != nil {
			util.LogWithContextIfNeeded("failed to reload tun device", err, t.l)
		}
	})

	return t, nil
}

func (t *tun) addIp(cidr netip.Prefix) error {
	var err error

	// TODO use syscalls instead of exec.Command
	cmd := exec.Command("/sbin/ifconfig", t.Device, cidr.String(), cidr.Addr().String())
	t.l.Debug("command: ", cmd.String())
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to run 'ifconfig': %s", err)
	}

	cmd = exec.Command("/sbin/route", "-n", "add", "-net", cidr.String(), cidr.Addr().String())
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
	return t.addRoutes(false)
}

func (t *tun) Activate() error {
	for i := range t.vpnNetworks {
		err := t.addIp(t.vpnNetworks[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *tun) reload(c *config.C, initial bool) error {
	change, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !change {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, false)
	if err != nil {
		return err
	}

	// Teach nebula how to handle the routes before establishing them in the system table
	oldRoutes := t.Routes.Swap(&routes)
	t.routeTree.Store(routeTree)

	if !initial {
		// Remove first, if the system removes a wanted route hopefully it will be re-added next
		err := t.removeRoutes(findRemovedRoutes(routes, *oldRoutes))
		if err != nil {
			util.LogWithContextIfNeeded("Failed to remove routes", err, t.l)
		}

		// Ensure any routes we actually want are installed
		err = t.addRoutes(true)
		if err != nil {
			// Catch any stray logs
			util.LogWithContextIfNeeded("Failed to add routes", err, t.l)
		}
	}

	return nil
}

func (t *tun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *tun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *tun) Name() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for netbsd")
}

func (t *tun) addRoutes(logErrors bool) error {
	routes := *t.Routes.Load()
	for _, r := range routes {
		if len(r.Via) == 0 || !r.Install {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		cmd := exec.Command("/sbin/route", "-n", "add", "-net", r.Cidr.String(), t.vpnNetworks[0].Addr().String())
		t.l.Debug("command: ", cmd.String())
		if err := cmd.Run(); err != nil {
			retErr := util.NewContextualError("failed to run 'route add' for unsafe_route", map[string]any{"route": r}, err)
			if logErrors {
				retErr.Log(t.l)
			} else {
				return retErr
			}
		}
	}

	return nil
}

func (t *tun) removeRoutes(routes []Route) error {
	for _, r := range routes {
		if !r.Install {
			continue
		}

		//TODO: CERT-V2 is this right?
		cmd := exec.Command("/sbin/route", "-n", "delete", "-net", r.Cidr.String(), t.vpnNetworks[0].Addr().String())
		t.l.Debug("command: ", cmd.String())
		if err := cmd.Run(); err != nil {
			t.l.WithError(err).WithField("route", r).Error("Failed to remove route")
		} else {
			t.l.WithField("route", r).Info("Removed route")
		}
	}
	return nil
}

func (t *tun) deviceBytes() (o [16]byte) {
	for i, c := range t.Device {
		o[i] = byte(c)
	}
	return
}
