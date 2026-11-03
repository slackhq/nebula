//go:build linux && !android && !e2e_testing

package udp

import (
	"log/slog"
	"net/netip"
)

// sendQueues returns n ways for queues to send through c: queue 0 uses c, the others share c's socket with their own
// batch writer. WriteTo is a plain sendto and needs nothing per queue.
func sendQueues(l *slog.Logger, c Conn, n int, offloads bool) []Conn {
	qs := make([]Conn, n)
	sc, ok := c.(*StdConn)
	for q := range qs {
		if q == 0 || !ok {
			qs[q] = c
			continue
		}
		qs[q] = &sendQueueConn{StdConn: sc, bw: newBatchWriter(sc.sysFd, sc.isV4, l, offloads)}
	}
	return qs
}

// sendQueueConn sends through a StdConn's socket with its own batch writer. The StdConn owns the socket, it alone is
// reloaded and closed.
type sendQueueConn struct {
	*StdConn
	bw *batchWriter
}

func (s *sendQueueConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	return s.bw.WriteBatch(bufs, addrs)
}
