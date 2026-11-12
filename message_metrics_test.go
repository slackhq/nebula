package nebula

import (
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rxTxFixture builds a MessageMetrics with a known-shape rx/tx grid plus
// the unknown/invalid sentinel counters wired up to fresh registry slots
// so each test gets isolated counter values.
//
// Shape (len(rx) == len(tx) == 6):
//
//	[0] -> 1 sub-counter   (Rx[0][0])
//	[1] -> nil             (no slots; any subtype is out of range)
//	[2] -> 1 sub-counter   (Rx[2][0])
//	[3] -> 1 sub-counter
//	[4] -> 2 sub-counters  (Rx[4][0], Rx[4][1])
//	[5] -> 1 sub-counter
func rxTxFixture(t testing.TB, suffix string) *MessageMetrics {
	t.Helper()
	gen := func(dir string) [][]metrics.Counter {
		return [][]metrics.Counter{
			{metrics.GetOrRegisterCounter(dir+".0."+suffix, nil)},
			nil,
			{metrics.GetOrRegisterCounter(dir+".2."+suffix, nil)},
			{metrics.GetOrRegisterCounter(dir+".3."+suffix, nil)},
			{
				metrics.GetOrRegisterCounter(dir+".4.0."+suffix, nil),
				metrics.GetOrRegisterCounter(dir+".4.1."+suffix, nil),
			},
			{metrics.GetOrRegisterCounter(dir+".5."+suffix, nil)},
		}
	}
	return &MessageMetrics{
		rx:        gen("rx"),
		tx:        gen("tx"),
		rxUnknown: metrics.GetOrRegisterCounter("rxUnknown."+suffix, nil),
		txUnknown: metrics.GetOrRegisterCounter("txUnknown."+suffix, nil),
		rxInvalid: metrics.GetOrRegisterCounter("rxInvalid."+suffix, nil),
	}
}

func TestMessageMetrics_Rx(t *testing.T) {
	tests := []struct {
		name    string
		t       header.MessageType
		s       header.MessageSubType
		inc     int64
		wantHit string // "specific" | "unknown"
	}{
		{"valid (t=0, s=0) increments rx[0][0]", 0, 0, 1, "specific"},
		{"valid (t=4, s=1) increments rx[4][1] - distinct sub counter", 4, 1, 7, "specific"},
		{"valid (t=5, s=0) at the last populated type slot", 5, 0, 1, "specific"},
		{"subtype out of range for non-nil slot routes to unknown", 0, 1, 3, "unknown"},
		{"subtype out of range for nil slot routes to unknown", 1, 0, 3, "unknown"},
		{"type past end of rx slice routes to unknown", 6, 0, 5, "unknown"},
		{"both fields way out of range route to unknown", 255, 255, 9, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := rxTxFixture(t, t.Name())

			// Snapshot the relevant counter; we'll compute delta after the call.
			var watched metrics.Counter
			switch {
			case tc.wantHit == "specific" && int(tc.t) < len(m.rx) && int(tc.s) < len(m.rx[tc.t]):
				watched = m.rx[tc.t][tc.s]
			default:
				watched = m.rxUnknown
			}
			before := watched.Count()

			m.Rx(tc.t, tc.s, tc.inc)

			assert.Equal(t, tc.inc, watched.Count()-before,
				"the %q path must increment by exactly the requested delta", tc.wantHit)
		})
	}
}

func TestMessageMetrics_Tx(t *testing.T) {
	tests := []struct {
		name    string
		t       header.MessageType
		s       header.MessageSubType
		inc     int64
		wantHit string
	}{
		{"valid (t=0, s=0) increments tx[0][0]", 0, 0, 1, "specific"},
		{"valid (t=4, s=1) increments tx[4][1] - distinct sub counter", 4, 1, 11, "specific"},
		{"valid (t=5, s=0) at the last populated type slot", 5, 0, 1, "specific"},
		{"subtype out of range for non-nil slot routes to unknown", 0, 1, 3, "unknown"},
		{"subtype out of range for nil slot routes to unknown", 1, 0, 3, "unknown"},
		{"type past end of tx slice routes to unknown", 6, 0, 5, "unknown"},
		{"both fields way out of range route to unknown", 255, 255, 13, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := rxTxFixture(t, t.Name())

			var watched metrics.Counter
			switch {
			case tc.wantHit == "specific" && int(tc.t) < len(m.tx) && int(tc.s) < len(m.tx[tc.t]):
				watched = m.tx[tc.t][tc.s]
			default:
				watched = m.txUnknown
			}
			before := watched.Count()

			m.Tx(tc.t, tc.s, tc.inc)

			assert.Equal(t, tc.inc, watched.Count()-before,
				"the %q path must increment by exactly the requested delta", tc.wantHit)
		})
	}
}

func TestMessageMetrics_RxInvalid(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (*MessageMetrics, metrics.Counter) // returns m and the rxInvalid counter
		inc         int64
		wantDelta   int64
		expectPanic bool
	}{
		{
			name: "nil MessageMetrics is a noop",
			setup: func(t *testing.T) (*MessageMetrics, metrics.Counter) {
				return nil, nil
			},
			inc:       5,
			wantDelta: 0,
		},
		{
			name: "nil rxInvalid counter is a noop",
			setup: func(t *testing.T) (*MessageMetrics, metrics.Counter) {
				return &MessageMetrics{}, nil
			},
			inc:       5,
			wantDelta: 0,
		},
		{
			name: "non-nil rxInvalid counter is incremented",
			setup: func(t *testing.T) (*MessageMetrics, metrics.Counter) {
				c := metrics.GetOrRegisterCounter("rxInvalid.happy."+t.Name(), nil)
				return &MessageMetrics{rxInvalid: c}, c
			},
			inc:       7,
			wantDelta: 7,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, c := tc.setup(t)
			var before int64
			if c != nil {
				before = c.Count()
			}

			// All paths must NOT panic - operator-shaped contract.
			require.NotPanics(t, func() { m.RxInvalid(tc.inc) })

			if c != nil {
				assert.Equal(t, tc.wantDelta, c.Count()-before)
			}
		})
	}
}

func TestMessageMetrics_NilReceiverIsSafe(t *testing.T) {
	var m *MessageMetrics
	require.NotPanics(t, func() {
		m.Rx(0, 0, 1)
		m.Tx(0, 0, 1)
		m.RxInvalid(1)
	}, "all three methods must tolerate a nil *MessageMetrics receiver")
}

// BenchmarkMessageMetrics_Rx_Valid measures the hot path: a valid (t, s)
// that lands on a specific counter. This is the common case under load
// (one call per received packet matching a known message type).
func BenchmarkMessageMetrics_Rx_Valid(b *testing.B) {
	m := rxTxFixture(b, b.Name())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Rx(0, 0, 1)
	}
}

// BenchmarkMessageMetrics_Rx_Unknown measures the cold path: an out-of-
// range type lands on the unknown counter. Less common but possible
// when the peer sends a malformed or future-version message type.
func BenchmarkMessageMetrics_Rx_Unknown(b *testing.B) {
	m := rxTxFixture(b, b.Name())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Rx(100, 0, 1)
	}
}

// BenchmarkMessageMetrics_Tx_Valid mirrors the Rx benchmark on the tx
// grid; Tx is structurally identical to Rx so the numbers are expected
// to match within noise.
func BenchmarkMessageMetrics_Tx_Valid(b *testing.B) {
	m := rxTxFixture(b, b.Name())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Tx(0, 0, 1)
	}
}

func TestMessageMetrics_NilUnknownCounter(t *testing.T) {
	// A MessageMetrics whose unknown sentinels are nil should swallow
	// out-of-range hits silently rather than panic. newMessageMetricsOnlyRecvError
	// produces exactly this shape (no rxUnknown / txUnknown / rxInvalid).
	m := &MessageMetrics{
		rx: [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter("nilunknown.rx.recv_error", nil)},
		},
		tx: [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter("nilunknown.tx.recv_error", nil)},
		},
	}

	require.NotPanics(t, func() {
		// out-of-range type -> would hit unknown, but unknown is nil
		m.Rx(100, 0, 1)
		m.Tx(100, 0, 1)
		// nil subtype slot in a populated type slot
		m.Rx(0, 0, 1)
		m.Tx(0, 0, 1)
	}, "out-of-range hits must be silent when the unknown counter is nil")
}
