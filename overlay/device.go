package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

// defaultBatchBufSize is the per-Queue scratch size for Read. 65535 covers
// any single IP packet.
const defaultBatchBufSize = 65535

type Device interface {
	io.Closer
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	// Queues returns the device's packet queues, opening additional ones as
	// needed until there are n. Platforms without multiqueue support return
	// their single queue regardless of n, so callers must size reader loops
	// to len(result), not n; implementations never return more than n. An
	// error means a queue that should have opened could not; the caller owns
	// cleanup via Close. Called once, during interface activation.
	Queues(n int) ([]tio.Queue, error)
}
