//go:build e2e_testing
// +build e2e_testing

package overlay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/udp"
)

type TestTun struct {
	Device      string
	vpnNetworks []netip.Prefix
	Routes      []Route
	routeTree   *bart.Table[routing.Gateways]
	l           *slog.Logger

	closed    atomic.Bool
	rxPackets chan []byte // Packets to receive into nebula
	TxPackets chan []byte // Packets transmitted outside by nebula
}

func newTun(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, _ bool) (*TestTun, error) {
	_, routes, err := getAllRoutesFromConfig(c, vpnNetworks, true)
	if err != nil {
		return nil, err
	}
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	return &TestTun{
		Device:      c.GetString("tun.dev", ""),
		vpnNetworks: vpnNetworks,
		Routes:      routes,
		routeTree:   routeTree,
		l:           l,
		rxPackets:   make(chan []byte, 10),
		TxPackets:   make(chan []byte, 10),
	}, nil
}

func newTunFromFd(_ *config.C, _ *slog.Logger, _ int, _ []netip.Prefix) (*TestTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported")
}

// Send will place a byte array onto the receive queue for nebula to consume.
// These are unencrypted ip layer frames destined for another nebula node.
// packets should exit the udp side, capture them with udpConn.Get.
//
// Send copies the input via the freelist, so the caller is free to mutate
// or reuse it after the call returns.
func (t *TestTun) Send(packet []byte) {
	if t.closed.Load() {
		return
	}

	if t.l.Enabled(context.Background(), slog.LevelDebug) {
		t.l.Debug("Tun receiving injected packet", "dataLen", len(packet))
	}
	buf := acquireTunBuf(len(packet))
	copy(buf, packet)
	t.rxPackets <- buf
}

// Get will pull an unencrypted ip layer frame from the transmit queue
// nebula meant to send this message to some application on the local system
// packets were ingested from the udp side, you can send them with udpConn.Send
func (t *TestTun) Get(block bool) []byte {
	if block {
		return <-t.TxPackets
	}

	select {
	case p := <-t.TxPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (t *TestTun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Lookup(ip)
	return r
}

func (t *TestTun) Activate() error {
	return nil
}

func (t *TestTun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *TestTun) Name() string {
	return t.Device
}

func (t *TestTun) Write(b []byte) (n int, err error) {
	if t.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	packet := acquireTunBuf(len(b))
	copy(packet, b)
	t.TxPackets <- packet
	return len(b), nil
}

// ReleaseTunBuf returns a slice from TxPackets to the harness freelist, don't use the bytes after the call.
// Channel-backed instead of sync.Pool because putting a []byte in a sync.Pool escapes the slice header to heap.
func ReleaseTunBuf(b []byte) {
	if b == nil {
		return
	}
	select {
	case tunBufFreelist <- b:
	default:
		// Freelist full; drop the buffer for the GC.
	}
}

// tunBufFreelist retains the backing arrays for TestTun.Write so steady-state allocation drops to zero once the
// freelist has saturated for the current MTU.
var tunBufFreelist = make(chan []byte, 64)

func acquireTunBuf(n int) []byte {
	var b []byte
	select {
	case b = <-tunBufFreelist:
	default:
		b = make([]byte, 0, udp.MTU)
	}
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
	}
	return b
}

func (t *TestTun) Close() error {
	if t.closed.CompareAndSwap(false, true) {
		close(t.rxPackets)
		close(t.TxPackets)
	}
	return nil
}

func (t *TestTun) Read(b []byte) (int, error) {
	p, ok := <-t.rxPackets
	if !ok {
		return 0, os.ErrClosed
	}
	n := len(p)
	copy(b, p)
	// Send always pushes a freelist-acquired slice, return it once we've copied the bytes into the caller's buffer.
	select {
	case tunBufFreelist <- p:
	default:
	}
	return n, nil
}

func (t *TestTun) SupportsMultiqueue() bool {
	return false
}

func (t *TestTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented")
}
