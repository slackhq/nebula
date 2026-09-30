//go:build darwin || send_pipeline

package batch

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// pipeWriter records every WriteBatch a SendPipeline makes. It checks each packet's bytes against the sequence
// number they carry while the call is in progress, and can hold a call until the test releases it.
type pipeWriter struct {
	t *testing.T

	mu     sync.Mutex
	seqs   []uint32
	dsts   []netip.AddrPort
	calls  []int
	inCall [][]byte // the bufs of the call in progress, for overlap checks

	gate    chan struct{} // if not nil, each call waits for a receive from it
	entered chan int      // if not nil, each call sends its size here on entry
	short   int           // each call reports this many fewer written
	err     error
}

func (w *pipeWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	w.mu.Lock()
	w.inCall = bufs
	w.mu.Unlock()
	if w.entered != nil {
		w.entered <- len(bufs)
	}
	if w.gate != nil {
		<-w.gate
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, b := range bufs {
		seq := binary.BigEndian.Uint32(b)
		if !checkPkt(b, seq) {
			w.t.Errorf("packet %d changed while being sent", seq)
		}
		w.seqs = append(w.seqs, seq)
		w.dsts = append(w.dsts, addrs[i])
	}
	w.calls = append(w.calls, len(bufs))
	w.inCall = nil
	return max(len(bufs)-w.short, 0), w.err
}

func (w *pipeWriter) sent() ([]uint32, []netip.AddrPort, []int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]uint32(nil), w.seqs...), append([]netip.AddrPort(nil), w.dsts...), append([]int(nil), w.calls...)
}

// fillPkt writes seq and a pattern derived from it into b, as the encrypt step writes a slot.
func fillPkt(b []byte, seq uint32) {
	binary.BigEndian.PutUint32(b, seq)
	for i := 4; i < len(b); i++ {
		b[i] = byte(seq) ^ byte(i)
	}
}

func checkPkt(b []byte, seq uint32) bool {
	if len(b) < 4 || binary.BigEndian.Uint32(b) != seq {
		return false
	}
	for i := 4; i < len(b); i++ {
		if b[i] != byte(seq)^byte(i) {
			return false
		}
	}
	return true
}

func pktSize(seq uint32) int { return 16 + int(seq%97) }

var testDsts = []netip.AddrPort{
	netip.MustParseAddrPort("10.0.0.1:4242"),
	netip.MustParseAddrPort("10.0.0.2:4242"),
	netip.MustParseAddrPort("[fd00::3]:4242"),
}

// commit adds packet seq to p the way listenIn does: Begin, reserve, encrypt, commit, End.
func commit(p *SendPipeline, seq uint32, last bool) {
	sb := p.Begin()
	slot := sb.Reserve(pktSize(seq))
	fillPkt(slot, seq)
	sb.Commit(slot, testDsts[seq%uint32(len(testDsts))])
	p.End(last)
}

func TestSendPipelineOrder(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t}
	// A small arena makes the batches grow theirs, and a small maxWrite splits takes across several writes.
	p := NewSendPipeline(w, 16, 64, 5, nil)

	const n = 20000
	seq := uint32(0)
	for seq < n {
		// Reads of 1 to 40 packets, with an occasional pause so the sender goes idle and is woken.
		read := 1 + int(seq*7%40)
		for j := 0; j < read && seq < n; j++ {
			commit(p, seq, j == read-1 || seq == n-1)
			seq++
		}
		if seq%1000 < 40 {
			time.Sleep(50 * time.Microsecond)
		}
	}
	p.Close()

	seqs, dsts, calls := w.sent()
	require.Len(t, seqs, n)
	for i, s := range seqs {
		require.Equal(t, uint32(i), s, "packet %d out of order", i)
		require.Equal(t, testDsts[s%uint32(len(testDsts))], dsts[i])
	}
	for _, c := range calls {
		assert.LessOrEqual(t, c, 5, "WriteBatch got more than maxWrite")
		assert.Positive(t, c)
	}
}

func TestSendPipelineConcurrentPeersKeepOrder(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	// A slow writer makes the sender take many packets per write, interleaving the three peers in each batch.
	w := &pipeWriter{t: t}
	slow := &slowWriter{pipeWriter: w, d: 20 * time.Microsecond}
	p := NewSendPipeline(slow, 128, 128*64, 128, nil)
	const n = 5000
	for i := uint32(0); i < n; i++ {
		commit(p, i, i%8 == 7 || i == n-1)
	}
	p.Close()

	seqs, dsts, _ := w.sent()
	require.Len(t, seqs, n)
	last := map[netip.AddrPort]int64{}
	for i, s := range seqs {
		prev, ok := last[dsts[i]]
		if ok {
			require.Greater(t, int64(s), prev, "peer %v went backwards", dsts[i])
		}
		last[dsts[i]] = int64(s)
	}
}

type slowWriter struct {
	*pipeWriter
	d time.Duration
}

func (s *slowWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	time.Sleep(s.d)
	return s.pipeWriter.WriteBatch(bufs, addrs)
}

// TestSendPipelineBackpressureAndReuse holds the sender inside a write and checks that the producer can fill
// exactly one more batch, that none of its slots overlap the packets being written, and that the next Begin waits
// until the write returns.
func TestSendPipelineBackpressureAndReuse(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	const batchCap = 8
	w := &pipeWriter{t: t, gate: make(chan struct{}), entered: make(chan int, 16)}
	p := NewSendPipeline(w, batchCap, 64, 128, nil)

	seq := uint32(0)
	for ; seq < batchCap; seq++ {
		commit(p, seq, seq == batchCap-1)
	}
	require.Equal(t, batchCap, <-w.entered, "sender should take the first batch whole")

	w.mu.Lock()
	inFlight := append([][]byte(nil), w.inCall...)
	w.mu.Unlock()

	// The second batch fills while the first is being written, in slots that don't touch the first's bytes.
	for ; seq < 2*batchCap; seq++ {
		sb := p.Begin()
		slot := sb.Reserve(pktSize(seq))
		for _, b := range inFlight {
			assert.False(t, overlaps(slot, b), "slot for packet %d overlaps packet %d, still being sent", seq, binary.BigEndian.Uint32(b))
		}
		fillPkt(slot, seq)
		sb.Commit(slot, testDsts[0])
		p.End(true)
	}

	// Both batches are now spoken for, so the next Begin must wait for the write to return.
	begun := make(chan struct{})
	go func() {
		commit(p, seq, true)
		close(begun)
	}()
	select {
	case <-begun:
		t.Fatal("Begin returned with both batches in use: the pipeline is not bounded")
	case <-time.After(50 * time.Millisecond):
	}
	for i, b := range inFlight {
		assert.True(t, checkPkt(b, uint32(i)), "packet %d was overwritten before its send completed", i)
	}

	w.gate <- struct{}{} // first write returns; the sender swaps and starts on the second batch
	assert.Equal(t, batchCap, <-w.entered)
	select {
	case <-begun:
	case <-time.After(5 * time.Second):
		t.Fatal("Begin did not return after the sender freed a batch")
	}
	w.gate <- struct{}{}
	go func() {
		for range w.entered {
			w.gate <- struct{}{}
		}
	}()
	p.Close()
	close(w.entered)

	seqs, _, calls := w.sent()
	require.Len(t, seqs, 2*batchCap+1)
	for i, s := range seqs {
		assert.Equal(t, uint32(i), s)
	}
	assert.Equal(t, []int{batchCap, batchCap, 1}, calls)
}

func overlaps(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	a0, b0 := uintptr(unsafe.Pointer(&a[0])), uintptr(unsafe.Pointer(&b[0]))
	return a0 < b0+uintptr(len(b)) && b0 < a0+uintptr(len(a))
}

// TestSendPipelineBatchesBuildUp checks the point of the pipeline: while one write is in the kernel, everything the
// producer commits leaves together in the next write.
func TestSendPipelineBatchesBuildUp(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t, gate: make(chan struct{}), entered: make(chan int, 16)}
	p := NewSendPipeline(w, 128, 128*64, 128, nil)

	commit(p, 0, true)
	require.Equal(t, 1, <-w.entered)
	// Ten one-packet reads while the first write is held.
	for i := uint32(1); i <= 10; i++ {
		commit(p, i, true)
	}
	w.gate <- struct{}{}
	require.Equal(t, 10, <-w.entered, "packets queued during a write should go out in one WriteBatch")
	w.gate <- struct{}{}
	p.Close()

	_, _, calls := w.sent()
	assert.Equal(t, []int{1, 10}, calls)
}

func TestSendPipelineCloseFlushes(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t}
	p := NewSendPipeline(w, 32, 32*64, 128, nil)
	// End(false) never wakes the sender, so only Close's final take sends these.
	for i := uint32(0); i < 5; i++ {
		commit(p, i, false)
	}
	p.Close()
	p.Close() // idempotent
	seqs, _, _ := w.sent()
	assert.Equal(t, []uint32{0, 1, 2, 3, 4}, seqs)
}

func TestSendPipelineCloseEmpty(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t}
	p := NewSendPipeline(w, 4, 64, 128, nil)
	sb := p.Begin()
	p.End(true) // nothing committed: no write
	assert.Zero(t, sb.Len())
	p.Close()
	_, _, calls := w.sent()
	assert.Empty(t, calls)
}

// TestSendPipelineCloseWaitsForWrite checks that Close returns only after a write in progress has returned, so the
// caller can't free anything the sender still uses.
func TestSendPipelineCloseWaitsForWrite(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t, gate: make(chan struct{}), entered: make(chan int, 4)}
	p := NewSendPipeline(w, 4, 64, 128, nil)
	commit(p, 0, true)
	<-w.entered
	commit(p, 1, false)

	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned during a write")
	case <-time.After(50 * time.Millisecond):
	}
	w.gate <- struct{}{}
	<-w.entered // Close's final take writes packet 1
	w.gate <- struct{}{}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	seqs, _, _ := w.sent()
	assert.Equal(t, []uint32{0, 1}, seqs)
}

func TestSendPipelineOnWriteAndDrops(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	werr := errors.New("boom")
	w := &pipeWriter{t: t, short: 1, err: werr}
	type call struct {
		queued, written int
		err             error
	}
	var got []call
	p := NewSendPipeline(w, 16, 16*64, 4, func(q, n int, err error) {
		got = append(got, call{q, n, err}) // sender goroutine only
	})
	for i := uint32(0); i < 10; i++ {
		commit(p, i, false)
	}
	p.Close()

	assert.Equal(t, []call{{4, 3, werr}, {4, 3, werr}, {2, 1, werr}}, got)
}

// TestSendPipelineStressRace runs a producer against a sender whose writes take varying time, for the race
// detector, and checks nothing is lost, reordered or overwritten.
func TestSendPipelineStressRace(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	w := &pipeWriter{t: t}
	jitter := &jitterWriter{pipeWriter: w}
	p := NewSendPipeline(jitter, 32, 256, 16, nil)
	const n = 50000
	for i := uint32(0); i < n; i++ {
		commit(p, i, i%3 == 0)
	}
	p.Close()
	seqs, _, _ := w.sent()
	require.Len(t, seqs, n)
	for i, s := range seqs {
		if uint32(i) != s {
			t.Fatalf("packet %d arrived at %d", s, i)
		}
	}
}

type jitterWriter struct {
	*pipeWriter
	i int
}

func (j *jitterWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	j.i++
	if j.i%7 == 0 {
		time.Sleep(time.Duration(j.i%5) * 10 * time.Microsecond)
	}
	return j.pipeWriter.WriteBatch(bufs, addrs)
}

type discardWriter struct{}

func (discardWriter) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	return len(bufs), nil
}

// BenchmarkSendPipeline measures a packet through Begin, reserve, commit and End with a writer that costs nothing;
// its allocs/op is the pipeline's steady-state heap cost per packet.
func BenchmarkSendPipeline(b *testing.B) {
	p := NewSendPipeline(discardWriter{}, SendBatchCap, SendBatchCap*1500, 128, nil)
	defer p.Close()
	b.ReportAllocs()
	for i := range b.N {
		sb := p.Begin()
		sb.Commit(sb.Reserve(1400), testDsts[0])
		p.End(i%8 == 7)
	}
}
