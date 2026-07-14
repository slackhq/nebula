package tio

import "io"

// singleQueue adapts a legacy one-datagram-per-Read source into a Queue.
// Read fills a private scratch buffer and returns exactly one Packet whose
// Bytes borrow from that buffer, valid only until the next Read, per the
// Queue contract. Single-reader like every Queue; Write is exactly as safe
// for concurrent use as the underlying source's Write.
type singleQueue struct {
	rw     io.ReadWriter
	closer io.Closer // nil: Close is a no-op (the source is shared and owned elsewhere)
	buf    []byte
	ret    [1]Packet
}

// NewSingleQueue wraps a one-datagram-per-Read ReadWriteCloser (a legacy tun
// device) into a Queue. bufSize is the per-queue read scratch size and must
// be at least the largest datagram the source can return. Close closes rwc.
func NewSingleQueue(rwc io.ReadWriteCloser, bufSize int) Queue {
	return &singleQueue{rw: rwc, closer: rwc, buf: make([]byte, bufSize)}
}

// NewSingleQueueNoClose is NewSingleQueue for a source owned by someone else,
// e.g. several queues sharing one device. Close on the returned Queue is a
// no-op so one queue can't tear the shared source out from under its
// siblings; the owner remains responsible for closing the source itself.
func NewSingleQueueNoClose(rw io.ReadWriter, bufSize int) Queue {
	return &singleQueue{rw: rw, buf: make([]byte, bufSize)}
}

func (q *singleQueue) Read() ([]Packet, error) {
	n, err := q.rw.Read(q.buf)
	if err != nil {
		return nil, err
	}
	q.ret[0] = Packet{Bytes: q.buf[:n]}
	return q.ret[:], nil
}

func (q *singleQueue) Write(p []byte) (int, error) {
	return q.rw.Write(p)
}

func (q *singleQueue) Close() error {
	if q.closer == nil {
		return nil
	}
	return q.closer.Close()
}
