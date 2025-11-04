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

	readMu      sync.Mutex
	readBuffers [][]byte
	readLens    []int
	legacyBuf   []byte

	writeMu      sync.Mutex
	writeBuf     []byte
	writeWrap    [][]byte
	writeBuffers [][]byte
}

func newWireguardTunIO(dev wgtun.Device, mtu int) *wireguardTunIO {
	batch := dev.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &wireguardTunIO{
		dev:       dev,
		mtu:       mtu,
		batchSize: batch,
		readLens:  make([]int, batch),
		legacyBuf: make([]byte, wgtun.VirtioNetHdrLen+mtu),
		writeBuf:  make([]byte, wgtun.VirtioNetHdrLen+mtu),
		writeWrap: make([][]byte, 1),
	}
}

func (w *wireguardTunIO) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	bufs := w.readBuffers
	if len(bufs) == 0 {
		bufs = [][]byte{w.legacyBuf}
		w.readBuffers = bufs
	}
	n, err := w.dev.Read(bufs[:1], w.readLens[:1], wgtun.VirtioNetHdrLen)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	length := w.readLens[0]
	copy(p, w.legacyBuf[wgtun.VirtioNetHdrLen:wgtun.VirtioNetHdrLen+length])
	return length, nil
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

func (w *wireguardTunIO) ReadIntoBatch(pool *PacketPool) ([]*Packet, error) {
	if pool == nil {
		return nil, fmt.Errorf("wireguard tun: packet pool is nil")
	}

	w.readMu.Lock()
	defer w.readMu.Unlock()

	if len(w.readBuffers) < w.batchSize {
		w.readBuffers = make([][]byte, w.batchSize)
	}
	if len(w.readLens) < w.batchSize {
		w.readLens = make([]int, w.batchSize)
	}

	packets := make([]*Packet, w.batchSize)
	requiredHeadroom := w.BatchHeadroom()
	requiredPayload := w.BatchPayloadCap()
	headroom := 0
	for i := 0; i < w.batchSize; i++ {
		pkt := pool.Get()
		if pkt == nil {
			releasePackets(packets[:i])
			return nil, fmt.Errorf("wireguard tun: packet pool returned nil packet")
		}
		if pkt.Capacity() < requiredPayload {
			pkt.Release()
			releasePackets(packets[:i])
			return nil, fmt.Errorf("wireguard tun: packet capacity %d below required %d", pkt.Capacity(), requiredPayload)
		}
		if i == 0 {
			headroom = pkt.Offset
			if headroom < requiredHeadroom {
				pkt.Release()
				releasePackets(packets[:i])
				return nil, fmt.Errorf("wireguard tun: packet headroom %d below virtio requirement %d", headroom, requiredHeadroom)
			}
		} else if pkt.Offset != headroom {
			pkt.Release()
			releasePackets(packets[:i])
			return nil, fmt.Errorf("wireguard tun: inconsistent packet headroom (%d != %d)", pkt.Offset, headroom)
		}
		packets[i] = pkt
		w.readBuffers[i] = pkt.Buf
	}

	n, err := w.dev.Read(w.readBuffers[:w.batchSize], w.readLens[:w.batchSize], headroom)
	if err != nil {
		releasePackets(packets)
		return nil, err
	}
	if n == 0 {
		releasePackets(packets)
		return nil, nil
	}
	for i := 0; i < n; i++ {
		packets[i].Len = w.readLens[i]
	}
	for i := n; i < w.batchSize; i++ {
		packets[i].Release()
		packets[i] = nil
	}
	return packets[:n], nil
}

func (w *wireguardTunIO) WriteBatch(packets []*Packet) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	requiredHeadroom := w.BatchHeadroom()
	offset := packets[0].Offset
	if offset < requiredHeadroom {
		releasePackets(packets)
		return 0, fmt.Errorf("wireguard tun: packet offset %d smaller than required headroom %d", offset, requiredHeadroom)
	}
	for _, pkt := range packets {
		if pkt == nil {
			continue
		}
		if pkt.Offset != offset {
			releasePackets(packets)
			return 0, fmt.Errorf("wireguard tun: mixed packet offsets not supported")
		}
		limit := pkt.Offset + pkt.Len
		if limit > len(pkt.Buf) {
			releasePackets(packets)
			return 0, fmt.Errorf("wireguard tun: packet length %d exceeds buffer capacity %d", pkt.Len, len(pkt.Buf)-pkt.Offset)
		}
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if len(w.writeBuffers) < len(packets) {
		w.writeBuffers = make([][]byte, len(packets))
	}
	for i, pkt := range packets {
		if pkt == nil {
			w.writeBuffers[i] = nil
			continue
		}
		limit := pkt.Offset + pkt.Len
		w.writeBuffers[i] = pkt.Buf[:limit]
	}
	n, err := w.dev.Write(w.writeBuffers[:len(packets)], offset)
	releasePackets(packets)
	return n, err
}

func (w *wireguardTunIO) BatchHeadroom() int {
	return wgtun.VirtioNetHdrLen
}

func (w *wireguardTunIO) BatchPayloadCap() int {
	return w.mtu
}

func (w *wireguardTunIO) BatchSize() int {
	return w.batchSize
}

func (w *wireguardTunIO) Close() error {
	return nil
}

func releasePackets(pkts []*Packet) {
	for _, pkt := range pkts {
		if pkt != nil {
			pkt.Release()
		}
	}
}
