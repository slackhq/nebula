package batch

import "github.com/slackhq/nebula/firewall"

// SortKey identifies a packet's position in its sender's transmission order.
// Epoch is a receiver-local ordinal for the tunnel (ConnectionState) that
// decrypted the packet. A re-handshake replaces the tunnel outright — new
// hostinfo, new keys, a fresh counter space — and the replacement's epoch is
// higher, so during the cutover overlap the old tunnel's packets sort first.
// Counter is the packet's AEAD message counter within that tunnel. The replay
// window has already rejected duplicates by Commit time, so keys are unique
// per tunnel and (Epoch, Counter) is a total order with no ties.
type SortKey struct {
	Epoch   uint64
	Counter uint64
}

type RxBatcher interface {
	// Commit stages pkt to be flushed by the batch. key must carry the
	// packet's session epoch and message counter; pp must be the firewall's
	// parse of this same packet. The caller must keep pkt valid until the
	// next Flush, and not re-use it. pp, by contrast, is borrowed only for
	// the duration of the call — the caller reuses one ParsedPacket per
	// receive loop — so implementations must copy what they need from it.
	Commit(pkt []byte, key SortKey, pp *firewall.ParsedPacket) error
	// Flush emits every staged packet. Packets are first sorted by key, so
	// within each protocol lane emission follows the sender's transmission
	// order regardless of arrival order. One shape may legally be overtaken
	// by later same-flow data: a pure TCP ACK, which does not close its
	// flow's open coalesce chain (a late ACK is just a stale ACK). Cross-lane
	// order (TCP vs UDP vs everything else) is not preserved.
	// Returns the first error observed; keeps draining so one bad packet
	// doesn't hold up the rest.
	// After Flush returns, committed payload slices may be recycled.
	Flush() error
}
