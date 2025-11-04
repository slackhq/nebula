//go:build linux && !android && !e2e_testing

package overlay

import (
	"fmt"
	"sync"

	wgtun "github.com/slackhq/nebula/wgstack/tun"
)

type wireguardTunIO struct {
	dev       wgtun.Device
	mtu       int
	batchSize int

	readMu   sync.Mutex
	readBufs [][]byte
	readLens []int
	pending  [][]byte
	pendIdx  int

	writeMu   sync.Mutex
	writeBuf  []byte
	writeWrap [][]byte
}

func newWireguardTunIO(dev wgtun.Device, mtu int) *wireguardTunIO {
	batch := dev.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, wgtun.VirtioNetHdrLen+mtu)
	}
	return &wireguardTunIO{
		dev:       dev,
		mtu:       mtu,
		batchSize: batch,
		readBufs:  bufs,
		readLens:  make([]int, batch),
		pending:   make([][]byte, 0, batch),
		writeBuf:  make([]byte, wgtun.VirtioNetHdrLen+mtu),
		writeWrap: make([][]byte, 1),
	}
}

func (w *wireguardTunIO) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	for {
		if w.pendIdx < len(w.pending) {
			segment := w.pending[w.pendIdx]
			w.pendIdx++
			n := copy(p, segment)
			return n, nil
		}

		n, err := w.dev.Read(w.readBufs, w.readLens, wgtun.VirtioNetHdrLen)
		if err != nil {
			return 0, err
		}
		w.pending = w.pending[:0]
		w.pendIdx = 0
		for i := 0; i < n; i++ {
			length := w.readLens[i]
			if length == 0 {
				continue
			}
			segment := w.readBufs[i][wgtun.VirtioNetHdrLen : wgtun.VirtioNetHdrLen+length]
			w.pending = append(w.pending, segment)
		}
	}
}

func (w *wireguardTunIO) Write(p []byte) (int, error) {
	if len(p) > w.mtu {
		return 0, fmt.Errorf("wireguard tun: payload exceeds MTU (%d > %d)", len(p), w.mtu)
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	buf := w.writeBuf[:wgtun.VirtioNetHdrLen+len(p)]
	for i := 0; i < wgtun.VirtioNetHdrLen; i++ {
		buf[i] = 0
	}
	copy(buf[wgtun.VirtioNetHdrLen:], p)
	w.writeWrap[0] = buf
	n, err := w.dev.Write(w.writeWrap, wgtun.VirtioNetHdrLen)
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func (w *wireguardTunIO) Close() error {
	return nil
}
