package batch

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingBatchWriter struct {
	calls [][]byte
}

func (w *recordingBatchWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	var run []byte
	for _, b := range bufs {
		run = append(run, b[0])
	}
	w.calls = append(w.calls, run)
	return len(bufs), nil
}

func TestSendBatchCommitPort(t *testing.T) {
	base := &recordingBatchWriter{}
	ports := map[uint16]*recordingBatchWriter{1: {}, 2: {}}
	b := NewSendBatch(base, 8, 0)
	b.SetPortWriter(func(port uint16) BatchWriter { return ports[port] })

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i, port := range []uint16{0, 2, 1, 2, 0, 1} {
		b.CommitPort([]byte{byte(i)}, ap, port)
	}
	n, err := b.Flush()
	if err != nil || n != 6 {
		t.Fatalf("Flush: n=%d err=%v", n, err)
	}

	// Each port gets one WriteBatch holding its packets in commit order
	check := func(name string, w *recordingBatchWriter, want []byte) {
		t.Helper()
		if len(w.calls) != 1 || string(w.calls[0]) != string(want) {
			t.Errorf("%s: got %v want one call of %v", name, w.calls, want)
		}
	}
	check("base", base, []byte{0, 4})
	check("port 1", ports[1], []byte{2, 5})
	check("port 2", ports[2], []byte{1, 3})

	// The next flush without nonzero ports goes straight to the base writer
	base.calls = nil
	b.CommitPort([]byte{9}, ap, 0)
	b.Commit([]byte{10}, ap)
	if _, err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	check("base second flush", base, []byte{9, 10})
}

func TestSendBatchCommitPortAllocs(t *testing.T) {
	base := noopBatchWriter{}
	b := NewSendBatch(base, 128, 0)
	b.SetPortWriter(func(uint16) BatchWriter { return base })
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	pkt := []byte{1}

	allocs := testing.AllocsPerRun(100, func() {
		for i := range 128 {
			b.CommitPort(pkt, ap, uint16(i%100))
		}
		_, _ = b.Flush()
	})
	if allocs != 0 {
		t.Fatalf("multiport flush allocated %v times per run", allocs)
	}
}

type noopBatchWriter struct{}

func (noopBatchWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	return len(bufs), nil
}

func TestSendBatchCommitPortBackfillPastCap(t *testing.T) {
	base := &recordingBatchWriter{}
	other := &recordingBatchWriter{}
	b := NewSendBatch(base, 2, 0)
	b.SetPortWriter(func(uint16) BatchWriter { return other })

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	// Commit past the batch cap on port 0 before the first nonzero port
	for i := range 3 {
		b.Commit([]byte{byte(i)}, ap)
	}
	b.CommitPort([]byte{3}, ap, 1)
	b.Commit([]byte{4}, ap)
	if n, err := b.Flush(); err != nil || n != 5 {
		t.Fatalf("Flush: n=%d err=%v", n, err)
	}
	if len(base.calls) != 1 || string(base.calls[0]) != string([]byte{0, 1, 2, 4}) {
		t.Errorf("base got %v", base.calls)
	}
	if len(other.calls) != 1 || string(other.calls[0]) != string([]byte{3}) {
		t.Errorf("port 1 got %v", other.calls)
	}
}

func TestSendBatchCommitPortOrders(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	tests := []struct {
		name  string
		ports []uint16
	}{
		// Every port in one run, sent straight from the batch
		{"grouped", []uint16{3, 3, 0, 0, 7, 9, 9}},
		// Ports split across runs and past 255, both radix passes
		{"scattered wide", []uint16{300, 5, 300, 256, 5, 0, 256, 300, 1, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writers := map[uint16]*recordingBatchWriter{0: {}}
			b := NewSendBatch(writers[0], 4, 0)
			b.SetPortWriter(func(port uint16) BatchWriter {
				if writers[port] == nil {
					writers[port] = &recordingBatchWriter{}
				}
				return writers[port]
			})

			want := map[uint16][]byte{}
			for i, port := range tt.ports {
				b.CommitPort([]byte{byte(i)}, ap, port)
				want[port] = append(want[port], byte(i))
			}
			if n, err := b.Flush(); err != nil || n != len(tt.ports) {
				t.Fatalf("Flush: n=%d err=%v", n, err)
			}
			for port, w := range writers {
				if len(w.calls) != 1 || string(w.calls[0]) != string(want[port]) {
					t.Errorf("port %d: got %v want one call of %v", port, w.calls, want[port])
				}
			}
			if len(writers) != len(want) {
				t.Errorf("wrote to %d ports, want %d", len(writers), len(want))
			}
		})
	}
}

type failingBatchWriter struct{}

func (failingBatchWriter) WriteBatch(_ [][]byte, _ []netip.AddrPort) (int, error) {
	return 0, errors.New("boom")
}

// A port whose write fails costs only its own packets, the error names the port and the other ports still send
func TestSendBatchFlushPortsPartialFailure(t *testing.T) {
	base := &recordingBatchWriter{}
	good := &recordingBatchWriter{}
	b := NewSendBatch(base, 8, 0)
	b.SetPortWriter(func(port uint16) BatchWriter {
		if port == 2 {
			return failingBatchWriter{}
		}
		return good
	})

	ap := netip.MustParseAddrPort("10.0.0.1:4242")
	for i, port := range []uint16{0, 1, 2, 2, 1} {
		b.CommitPort([]byte{byte(i)}, ap, port)
	}
	n, err := b.Flush()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiport send port 2")
	assert.Equal(t, 3, n)
	assert.Equal(t, [][]byte{{0}}, base.calls)
	assert.Equal(t, [][]byte{{1, 4}}, good.calls)
}
