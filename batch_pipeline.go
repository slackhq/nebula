package nebula

import (
	"net/netip"

	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/udp"
)

// batchPipelines tracks whether the inside device can operate on packet batches
// and, if so, holds the shared packet pool sized for the virtio headroom and
// payload limits advertised by the device. It also owns the fan-in/fan-out
// queues between the TUN readers, encrypt/decrypt workers, and the UDP writers.
type batchPipelines struct {
	enabled    bool
	inside     overlay.BatchCapableDevice
	headroom   int
	payloadCap int
	pool       *overlay.PacketPool
	batchSize  int
	routines   int
	rxQueues   []chan *overlay.Packet
	txQueues   []chan queuedDatagram
	tunQueues  []chan *overlay.Packet
}

type queuedDatagram struct {
	packet *overlay.Packet
	addr   netip.AddrPort
}

func (bp *batchPipelines) init(device overlay.Device, routines int, queueDepth int, maxSegments int) {
	if device == nil || routines <= 0 {
		return
	}
	bcap, ok := device.(overlay.BatchCapableDevice)
	if !ok {
		return
	}
	headroom := bcap.BatchHeadroom()
	payload := bcap.BatchPayloadCap()
	if maxSegments < 1 {
		maxSegments = 1
	}
	requiredPayload := udp.MTU * maxSegments
	if payload < requiredPayload {
		payload = requiredPayload
	}
	batchSize := bcap.BatchSize()
	if headroom <= 0 || payload <= 0 || batchSize <= 0 {
		return
	}
	bp.enabled = true
	bp.inside = bcap
	bp.headroom = headroom
	bp.payloadCap = payload
	bp.batchSize = batchSize
	bp.routines = routines
	bp.pool = overlay.NewPacketPool(headroom, payload)
	queueCap := batchSize * defaultBatchQueueDepthFactor
	if queueDepth > 0 {
		queueCap = queueDepth
	}
	if queueCap < batchSize {
		queueCap = batchSize
	}
	bp.rxQueues = make([]chan *overlay.Packet, routines)
	bp.txQueues = make([]chan queuedDatagram, routines)
	bp.tunQueues = make([]chan *overlay.Packet, routines)
	for i := 0; i < routines; i++ {
		bp.rxQueues[i] = make(chan *overlay.Packet, queueCap)
		bp.txQueues[i] = make(chan queuedDatagram, queueCap)
		bp.tunQueues[i] = make(chan *overlay.Packet, queueCap)
	}
}

func (bp *batchPipelines) Pool() *overlay.PacketPool {
	if bp == nil || !bp.enabled {
		return nil
	}
	return bp.pool
}

func (bp *batchPipelines) Enabled() bool {
	return bp != nil && bp.enabled
}

func (bp *batchPipelines) batchSizeHint() int {
	if bp == nil || bp.batchSize <= 0 {
		return 1
	}
	return bp.batchSize
}

func (bp *batchPipelines) rxQueue(i int) chan *overlay.Packet {
	if bp == nil || !bp.enabled || i < 0 || i >= len(bp.rxQueues) {
		return nil
	}
	return bp.rxQueues[i]
}

func (bp *batchPipelines) txQueue(i int) chan queuedDatagram {
	if bp == nil || !bp.enabled || i < 0 || i >= len(bp.txQueues) {
		return nil
	}
	return bp.txQueues[i]
}

func (bp *batchPipelines) tunQueue(i int) chan *overlay.Packet {
	if bp == nil || !bp.enabled || i < 0 || i >= len(bp.tunQueues) {
		return nil
	}
	return bp.tunQueues[i]
}

func (bp *batchPipelines) txQueueLen(i int) int {
	q := bp.txQueue(i)
	if q == nil {
		return 0
	}
	return len(q)
}

func (bp *batchPipelines) tunQueueLen(i int) int {
	q := bp.tunQueue(i)
	if q == nil {
		return 0
	}
	return len(q)
}

func (bp *batchPipelines) enqueueRx(i int, pkt *overlay.Packet) bool {
	q := bp.rxQueue(i)
	if q == nil {
		return false
	}
	q <- pkt
	return true
}

func (bp *batchPipelines) enqueueTx(i int, pkt *overlay.Packet, addr netip.AddrPort) bool {
	q := bp.txQueue(i)
	if q == nil {
		return false
	}
	q <- queuedDatagram{packet: pkt, addr: addr}
	return true
}

func (bp *batchPipelines) enqueueTun(i int, pkt *overlay.Packet) bool {
	q := bp.tunQueue(i)
	if q == nil {
		return false
	}
	q <- pkt
	return true
}

func (bp *batchPipelines) newPacket() *overlay.Packet {
	if bp == nil || !bp.enabled || bp.pool == nil {
		return nil
	}
	return bp.pool.Get()
}
