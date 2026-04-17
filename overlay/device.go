package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/routing"
)

// defaultBatchBufSize is the per-Queue scratch size for ReadBatch on backends
// that don't do TSO segmentation. 65535 covers any single IP packet.
const defaultBatchBufSize = 65535

// Queue is a readable/writable tun queue. ReadBatch returns one or more
// packets; the returned slices are borrowed from the queue's internal buffer
// and are only valid until the next ReadBatch / Read / Close on this Queue.
// Callers must encrypt or copy each slice before the next call. Not safe for
// concurrent use — one goroutine per Queue.
type Queue interface {
	io.ReadWriteCloser
	ReadBatch() ([][]byte, error)
}

type Device interface {
	Queue
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() (Queue, error)
}

// GSOWriter is implemented by Queues that can write a TCP TSO superpacket as
// a single virtio_net_hdr + payload writev, letting the kernel segment on
// egress. Callers type-assert on it; backends that don't support GSO return
// false from Supported and all coalescing logic is skipped.
//
// pkt must contain the IPv4/IPv6 + TCP header plus the concatenated
// coalesced payload. hdrLen is the total L3+L4 header length (where the
// payload starts). csumStart is the byte offset where the TCP header
// begins (= IP header length). gsoSize is the MSS — every segment except
// possibly the last must be exactly this many payload bytes. isV6 selects
// GSO_TCPV4 vs GSO_TCPV6.
//
// pkt's TCP checksum field must already hold the pseudo-header partial
// sum (single-fold, not inverted), per virtio NEEDS_CSUM semantics.
type GSOWriter interface {
	WriteGSO(pkt []byte, gsoSize uint16, isV6 bool, hdrLen, csumStart uint16) error
	GSOSupported() bool
}
