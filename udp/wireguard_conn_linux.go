//go:build linux && !android && !e2e_testing

package udp

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	wgconn "github.com/slackhq/nebula/wgstack/conn"
)

// WGConn adapts WireGuard's batched UDP bind implementation to Nebula's udp.Conn interface.
type WGConn struct {
	l         *logrus.Logger
	bind      *wgconn.StdNetBind
	recvers   []wgconn.ReceiveFunc
	batch     int
	reqBatch  int
	localIP   netip.Addr
	localPort uint16
	enableGSO bool
	enableGRO bool
	gsoMaxSeg int
	closed    atomic.Bool

	closeOnce sync.Once
}

// NewWireguardListener creates a UDP listener backed by WireGuard's StdNetBind.
func NewWireguardListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	bind := wgconn.NewStdNetBindForAddr(ip, multi)
	recvers, actualPort, err := bind.Open(uint16(port))
	if err != nil {
		return nil, err
	}
	if batch <= 0 {
		batch = bind.BatchSize()
	} else if batch > bind.BatchSize() {
		batch = bind.BatchSize()
	}
	return &WGConn{
		l:         l,
		bind:      bind,
		recvers:   recvers,
		batch:     batch,
		reqBatch:  batch,
		localIP:   ip,
		localPort: actualPort,
	}, nil
}

func (c *WGConn) Rebind() error {
	// WireGuard's bind does not support rebinding in place.
	return nil
}

func (c *WGConn) LocalAddr() (netip.AddrPort, error) {
	if !c.localIP.IsValid() || c.localIP.IsUnspecified() {
		// Fallback to wildcard IPv4 for display purposes.
		return netip.AddrPortFrom(netip.IPv4Unspecified(), c.localPort), nil
	}
	return netip.AddrPortFrom(c.localIP, c.localPort), nil
}

func (c *WGConn) listen(fn wgconn.ReceiveFunc, r EncReader) {
	batchSize := c.batch
	packets := make([][]byte, batchSize)
	for i := range packets {
		packets[i] = make([]byte, MTU)
	}
	sizes := make([]int, batchSize)
	endpoints := make([]wgconn.Endpoint, batchSize)

	for {
		if c.closed.Load() {
			return
		}
		n, err := fn(packets, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if c.l != nil {
				c.l.WithError(err).Debug("wireguard UDP listener receive error")
			}
			continue
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			stdEp, ok := endpoints[i].(*wgconn.StdNetEndpoint)
			if !ok {
				if c.l != nil {
					c.l.Warn("wireguard UDP listener received unexpected endpoint type")
				}
				continue
			}
			addr := stdEp.AddrPort
			r(addr, packets[i][:sizes[i]])
			endpoints[i] = nil
		}
	}
}

func (c *WGConn) ListenOut(r EncReader) {
	for _, fn := range c.recvers {
		go c.listen(fn, r)
	}
}

func (c *WGConn) WriteTo(b []byte, addr netip.AddrPort) error {
	if len(b) == 0 {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	ep := &wgconn.StdNetEndpoint{AddrPort: addr}
	return c.bind.Send([][]byte{b}, ep)
}

func (c *WGConn) WriteBatch(datagrams []Datagram) error {
	if len(datagrams) == 0 {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	max := c.batch
	if max <= 0 {
		max = len(datagrams)
		if max == 0 {
			max = 1
		}
	}
	bufs := make([][]byte, 0, max)
	var (
		current  netip.AddrPort
		endpoint *wgconn.StdNetEndpoint
		haveAddr bool
	)
	flush := func() error {
		if len(bufs) == 0 || endpoint == nil {
			bufs = bufs[:0]
			return nil
		}
		err := c.bind.Send(bufs, endpoint)
		bufs = bufs[:0]
		return err
	}

	for _, d := range datagrams {
		if len(d.Payload) == 0 || !d.Addr.IsValid() {
			continue
		}
		if !haveAddr || d.Addr != current {
			if err := flush(); err != nil {
				return err
			}
			current = d.Addr
			endpoint = &wgconn.StdNetEndpoint{AddrPort: current}
			haveAddr = true
		}
		bufs = append(bufs, d.Payload)
		if len(bufs) >= max {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

func (c *WGConn) ConfigureOffload(enableGSO, enableGRO bool, maxSegments int) {
	c.enableGSO = enableGSO
	c.enableGRO = enableGRO
	if maxSegments <= 0 {
		maxSegments = 1
	} else if maxSegments > wgconn.IdealBatchSize {
		maxSegments = wgconn.IdealBatchSize
	}
	c.gsoMaxSeg = maxSegments

	effectiveBatch := c.reqBatch
	if enableGSO && c.bind != nil {
		bindBatch := c.bind.BatchSize()
		if effectiveBatch < bindBatch {
			if c.l != nil {
				c.l.WithFields(logrus.Fields{
					"requested": c.reqBatch,
					"effective": bindBatch,
				}).Warn("listen.batch below wireguard minimum; using bind batch size for UDP GSO support")
			}
			effectiveBatch = bindBatch
		}
	}
	c.batch = effectiveBatch

	if c.l != nil {
		c.l.WithFields(logrus.Fields{
			"enableGSO":      enableGSO,
			"enableGRO":      enableGRO,
			"gsoMaxSegments": maxSegments,
		}).Debug("configured wireguard UDP offload")
	}
}

func (c *WGConn) ReloadConfig(*config.C) {
	// WireGuard bind currently does not expose runtime configuration knobs.
}

func (c *WGConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		err = c.bind.Close()
	})
	return err
}
