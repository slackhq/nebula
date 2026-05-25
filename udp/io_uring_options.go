package udp

import (
	"log/slog"
	"math/bits"

	"github.com/slackhq/nebula/config"
)

// IoUringOptions carries the tunables for the io_uring-backed Conn. All
// fields are read once at NewListenerSelector and not reloadable — ring
// sizes are fixed at kernel-side setup time.
//
// Defaults come from DefaultIoUringOptions. When io_uring is disabled
// (Enabled=false) or the binary lacks the iouring build tag, the size
// fields are ignored.
type IoUringOptions struct {
	// Enabled selects the io_uring-backed Conn at runtime. Requires the
	// binary to be built with -tags iouring AND the kernel to advertise
	// IORING_OP_RECVMSG / IORING_OP_SENDMSG.
	Enabled bool

	// RecvRingSize is the SQE/CQE depth of the receive ring. Must be a
	// power of two in [1, 32768] per the io_uring_setup(2) contract; non-
	// power-of-two values are rounded up at NewIoUringListener time with
	// a log warning. Larger rings let more recv SQEs sit in flight before
	// userland needs to drain the completion queue; 512 is a comfortable
	// default for batch=64 with GRO.
	RecvRingSize int

	// SendRingSize is the SQE/CQE depth of the send ring. Same rules as
	// RecvRingSize. Affects how large a WriteBatch can submit before the
	// kernel pushes back; the synchronous completion drain means each
	// WriteBatch fills at most ioUringSendSlots SQEs regardless.
	SendRingSize int

	// RecvSlots is the number of pre-armed recv SQEs kept resident on the
	// ring. The kernel can land arriving packets into any pre-armed slot
	// without waiting for userland to resubmit, so this caps how much
	// burst the ring can absorb under sustained pps. Must be <= RecvRingSize.
	RecvSlots int

	// SendSlots is the number of concurrent in-flight send SQEs each send
	// ring holds. Synchronous completion drain at the end of each
	// WriteBatch returns them to the free list before the next batch
	// begins; this bounds peak burst depth per ring, not steady-state
	// throughput. Must be <= SendRingSize. Note: this is per-ring, so
	// total send slot memory scales as SendRings * SendSlots * 65 KiB.
	SendSlots int

	// SendRings is the number of independent send rings the Conn opens.
	// Each ring has its own slots, sendFree channel, and mutex. WriteTo
	// and WriteBatch pick a ring via an atomic round-robin counter with
	// a TryLock scan, so concurrent senders contend at most 1/SendRings
	// on average. Cap is 32 (anything more burns memory for diminishing
	// returns); default is 4 (one in-flight send per ring × 4 = enough
	// concurrency for the multi-writer outside Conn on a typical box).
	SendRings int
}

// MaxSendRings is the upper bound on IoUringOptions.SendRings. Each ring
// costs ~16 KiB of kernel mmap plus SendSlots * 65 KiB of payload buffers,
// so 32 rings at default slots already use ~530 MiB per Conn — anything
// beyond that is almost certainly tuning past the point of usefulness.
const MaxSendRings = 32

// DefaultIoUringOptions returns the baseline tuning. Picked to match the
// recvmmsg path's batch=64 default with comfortable headroom: 512-entry
// rings, 256 pre-armed slots on each side, and 4 send rings (so the
// multi-writer outside Conn has ~1.25 writers per ring on average).
func DefaultIoUringOptions() IoUringOptions {
	return IoUringOptions{
		Enabled:      false,
		RecvRingSize: 512,
		SendRingSize: 512,
		RecvSlots:    256,
		SendSlots:    256,
		SendRings:    4,
	}
}

// IoUringOptionsFromConfig reads the listen.io_uring* keys into an
// IoUringOptions, falling back to DefaultIoUringOptions for any unset key.
// Validation (power-of-two ring sizes, slots <= ring size) happens at
// NewIoUringListener so a misconfigured value gets a log line at startup
// rather than failing config parsing silently.
func IoUringOptionsFromConfig(c *config.C) IoUringOptions {
	d := DefaultIoUringOptions()
	return IoUringOptions{
		Enabled:      c.GetBool("listen.io_uring", false),
		RecvRingSize: c.GetInt("listen.io_uring_recv_ring_size", d.RecvRingSize),
		SendRingSize: c.GetInt("listen.io_uring_send_ring_size", d.SendRingSize),
		RecvSlots:    c.GetInt("listen.io_uring_recv_slots", d.RecvSlots),
		SendSlots:    c.GetInt("listen.io_uring_send_slots", d.SendSlots),
		SendRings:    c.GetInt("listen.io_uring_send_rings", d.SendRings),
	}
}

// validateIoUringOptions normalizes an IoUringOptions in place: ring sizes
// get clamped to [1, 32768] and rounded up to the next power of two if
// needed; slot counts get clamped to (0, ring size]. Any adjustment is
// logged so an operator sees their setting was overridden. Returns the
// (possibly mutated) options for chaining.
func validateIoUringOptions(opts IoUringOptions, l *slog.Logger) IoUringOptions {
	d := DefaultIoUringOptions()
	opts.RecvRingSize = clampAndRoundRing(opts.RecvRingSize, d.RecvRingSize, "listen.io_uring_recv_ring_size", l)
	opts.SendRingSize = clampAndRoundRing(opts.SendRingSize, d.SendRingSize, "listen.io_uring_send_ring_size", l)
	opts.RecvSlots = clampSlots(opts.RecvSlots, opts.RecvRingSize, d.RecvSlots, "listen.io_uring_recv_slots", l)
	opts.SendSlots = clampSlots(opts.SendSlots, opts.SendRingSize, d.SendSlots, "listen.io_uring_send_slots", l)
	opts.SendRings = clampSendRings(opts.SendRings, d.SendRings, l)
	return opts
}

// clampSendRings normalizes SendRings into [1, MaxSendRings]. Zero or
// negative values fall back to the default; values above the cap are
// clamped down with a log warning so operators learn what they actually
// got.
func clampSendRings(got, def int, l *slog.Logger) int {
	if got <= 0 {
		return def
	}
	if got > MaxSendRings {
		l.Warn("io_uring config: send_rings exceeds cap, clamping",
			"key", "listen.io_uring_send_rings", "requested", got, "max", MaxSendRings)
		return MaxSendRings
	}
	return got
}

// ioUringMaxRingEntries is the kernel-imposed ceiling on io_uring_setup(2)
// entries (IORING_MAX_ENTRIES). Anything above this would be rejected by
// the kernel; we clamp at config time so operators see a clear log message
// rather than a setup failure.
const ioUringMaxRingEntries = 32768

func clampAndRoundRing(got, def int, key string, l *slog.Logger) int {
	if got <= 0 {
		return def
	}
	if got > ioUringMaxRingEntries {
		l.Warn("io_uring config: ring size exceeds kernel max, clamping",
			"key", key, "requested", got, "max", ioUringMaxRingEntries)
		got = ioUringMaxRingEntries
	}
	if got&(got-1) != 0 {
		// Round up to next power of two — io_uring_setup rejects non-pow2.
		rounded := 1 << bits.Len(uint(got))
		if rounded > ioUringMaxRingEntries {
			rounded = ioUringMaxRingEntries
		}
		l.Warn("io_uring config: ring size not a power of 2, rounding up",
			"key", key, "requested", got, "using", rounded)
		got = rounded
	}
	return got
}

func clampSlots(got, ringSize, def int, key string, l *slog.Logger) int {
	if got <= 0 {
		got = def
	}
	if got > ringSize {
		l.Warn("io_uring config: slots exceed ring size, capping",
			"key", key, "requested", got, "ring_size", ringSize)
		got = ringSize
	}
	return got
}
