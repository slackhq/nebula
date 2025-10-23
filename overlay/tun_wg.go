//go:build !android && !netbsd && !e2e_testing
// +build !android,!netbsd,!e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/util"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// wgTun wraps a WireGuard TUN device and implements the overlay.Device interface
type wgTun struct {
	tunDevice   wgtun.Device
	vpnNetworks []netip.Prefix
	MaxMTU      int
	DefaultMTU  int

	Routes    atomic.Pointer[[]Route]
	routeTree atomic.Pointer[bart.Table[routing.Gateways]]
	routeChan chan struct{}

	// Platform-specific route management
	routeManager *tun

	l *logrus.Logger
}

// BatchReader interface for readers that support vectorized I/O
type BatchReader interface {
	BatchRead(buffers [][]byte, sizes []int) (int, error)
}

// BatchWriter interface for writers that support vectorized I/O
type BatchWriter interface {
	BatchWrite(packets [][]byte) (int, error)
}

// wgTunReader wraps a single TUN queue for multi-queue support
type wgTunReader struct {
	parent    *wgTun
	tunDevice wgtun.Device
	offset    int
	l         *logrus.Logger
}

func (t *wgTun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *wgTun) Name() string {
	name, err := t.tunDevice.Name()
	if err != nil {
		t.l.WithError(err).Error("Failed to get TUN device name")
		return "unknown"
	}
	return name
}

func (t *wgTun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Load().Lookup(ip)
	return r
}

func (t *wgTun) Activate() error {
	if t.routeManager == nil {
		return fmt.Errorf("route manager not initialized")
	}
	return t.routeManager.Activate(t)
}

// Read implements single-packet read for backward compatibility
func (t *wgTun) Read(b []byte) (int, error) {
	bufs := [][]byte{b}
	sizes := []int{0}
	n, err := t.tunDevice.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrNoProgress
	}
	return sizes[0], nil
}

// Write implements single-packet write for backward compatibility
func (t *wgTun) Write(b []byte) (int, error) {
	bufs := [][]byte{b}
	offset := 0

	// WireGuard TUN expects the packet data to start at offset 0
	n, err := t.tunDevice.Write(bufs, offset)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (t *wgTun) Close() error {
	if t.routeChan != nil {
		close(t.routeChan)
	}

	if t.tunDevice != nil {
		return t.tunDevice.Close()
	}

	return nil
}

func (t *wgTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	// For WireGuard TUN, we need to create separate TUN device instances for multi-queue
	// The platform-specific implementation will handle this
	if t.routeManager == nil {
		return nil, fmt.Errorf("route manager not initialized for multi-queue reader")
	}

	return t.routeManager.NewMultiQueueReader(t)
}

func (t *wgTun) reload(c *config.C, initial bool) error {
	routeChange, routes, err := getAllRoutesFromConfig(c, t.vpnNetworks, initial)
	if err != nil {
		return err
	}

	if !initial && !routeChange && !c.HasChanged("tun.mtu") {
		return nil
	}

	routeTree, err := makeRouteTree(t.l, routes, true)
	if err != nil {
		return err
	}

	oldDefaultMTU := t.DefaultMTU
	oldMaxMTU := t.MaxMTU
	newDefaultMTU := c.GetInt("tun.mtu", DefaultMTU)
	newMaxMTU := newDefaultMTU
	for i, r := range routes {
		if r.MTU == 0 {
			routes[i].MTU = newDefaultMTU
		}

		if r.MTU > t.MaxMTU {
			newMaxMTU = r.MTU
		}
	}

	t.MaxMTU = newMaxMTU
	t.DefaultMTU = newDefaultMTU

	// Teach nebula how to handle the routes before establishing them in the system table
	oldRoutes := t.Routes.Swap(&routes)
	t.routeTree.Store(routeTree)

	if !initial && t.routeManager != nil {
		if oldMaxMTU != newMaxMTU {
			t.routeManager.SetMTU(t, t.MaxMTU)
			t.l.Infof("Set max MTU to %v was %v", t.MaxMTU, oldMaxMTU)
		}

		if oldDefaultMTU != newDefaultMTU {
			for i := range t.vpnNetworks {
				err := t.routeManager.SetDefaultRoute(t, t.vpnNetworks[i])
				if err != nil {
					t.l.Warn(err)
				} else {
					t.l.Infof("Set default MTU to %v was %v", t.DefaultMTU, oldDefaultMTU)
				}
			}
		}

		// Remove first, if the system removes a wanted route hopefully it will be re-added next
		t.routeManager.RemoveRoutes(t, findRemovedRoutes(routes, *oldRoutes))

		// Ensure any routes we actually want are installed
		err = t.routeManager.AddRoutes(t, true)
		if err != nil {
			// This should never be called since AddRoutes should log its own errors in a reload condition
			util.LogWithContextIfNeeded("Failed to refresh routes", err, t.l)
		}
	}

	return nil
}

// BatchRead reads multiple packets from the TUN device using vectorized I/O
// The caller provides buffers and sizes slices, and this function returns the number of packets read.
func (r *wgTunReader) BatchRead(buffers [][]byte, sizes []int) (int, error) {
	return r.tunDevice.Read(buffers, sizes, r.offset)
}

// Read implements io.Reader for wgTunReader (single packet for compatibility)
func (r *wgTunReader) Read(b []byte) (int, error) {
	bufs := [][]byte{b}
	sizes := []int{0}
	n, err := r.tunDevice.Read(bufs, sizes, r.offset)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrNoProgress
	}
	return sizes[0], nil
}

// Write implements io.Writer for wgTunReader
func (r *wgTunReader) Write(b []byte) (int, error) {
	bufs := [][]byte{b}
	n, err := r.tunDevice.Write(bufs, r.offset)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

// BatchWrite writes multiple packets to the TUN device using vectorized I/O
func (r *wgTunReader) BatchWrite(packets [][]byte) (int, error) {
	return r.tunDevice.Write(packets, r.offset)
}

func (r *wgTunReader) Close() error {
	if r.tunDevice != nil {
		return r.tunDevice.Close()
	}
	return nil
}
