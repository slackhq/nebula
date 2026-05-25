//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"sync"
)

// ioUringRxBufferSize is the per-slot RX buffer. Sized to udpGROBufferSize so
// a maximally coalesced UDP_GRO superpacket lands intact in a single buffer.
const ioUringRxBufferSize = udpGROBufferSize

type ioRxBuffer = [ioUringRxBufferSize]byte

// rxBufferPool hands out fixed-size RX payload buffers to recv and send
// slots. Returned via putRxBuffer when the slot is recycled. The zero value
// is a live pool; New is set lazily so the first Get on a fresh process
// allocates. cmsg scratch is held inline on each slot rather than pooled —
// the layout is small enough (~48 bytes) that pooling it would cost more
// than it saved.
var rxBufferPool = sync.Pool{
	New: func() any {
		var b ioRxBuffer
		return &b
	},
}

func getRxBuffer() *ioRxBuffer {
	return rxBufferPool.Get().(*ioRxBuffer)
}

func putRxBuffer(b *ioRxBuffer) {
	if b == nil {
		return
	}
	rxBufferPool.Put(b)
}
