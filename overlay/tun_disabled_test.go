package overlay

import (
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func disabledTunEchoPacket(tb testing.TB, ipv6 bool) []byte {
	tb.Helper()
	raw := "4500001c00000000400100000a0000010a0000020800000000010001"
	if ipv6 {
		raw = "6000000000083a40fd000000000000000000000000000001fd0000000000000000000000000000028000000000010001"
	}
	packet, err := hex.DecodeString(raw)
	require.NoError(tb, err)
	return packet
}

func TestDisabledTunPackets(t *testing.T) {
	tests := []struct {
		name, description string
		packet            []byte
		capacity, writes  int
		closeFirst        bool
		expected          int // queued replies
	}{
		{name: "ipv4", description: "an echo request produces one reply", packet: disabledTunEchoPacket(t, false), capacity: 1, writes: 1, expected: 1},
		{name: "ipv6", description: "an IPv6 echo request produces one reply", packet: disabledTunEchoPacket(t, true), capacity: 1, writes: 1, expected: 1},
		{name: "empty", description: "empty input is discarded", packet: nil, capacity: 1, writes: 1, expected: 0},
		{name: "truncated", description: "a truncated header is discarded", packet: []byte{0x45}, capacity: 1, writes: 1, expected: 0},
		{name: "non_echo", description: "an echo reply does not generate another reply", packet: append(disabledTunEchoPacket(t, false)[:20], make([]byte, 8)...), capacity: 1, writes: 1, expected: 0},
		{name: "unbuffered", description: "without a waiting reader a zero-capacity queue drops", packet: disabledTunEchoPacket(t, false), capacity: 0, writes: 1, expected: 0},
		{name: "full", description: "a full queue drops the next reply without blocking", packet: disabledTunEchoPacket(t, false), capacity: 1, writes: 2, expected: 1},
		{name: "closed", description: "writes after closure succeed but enqueue nothing", packet: disabledTunEchoPacket(t, false), capacity: 1, writes: 1, closeFirst: true, expected: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			device := newDisabledTun(nil, tc.capacity, false, slog.New(slog.DiscardHandler))
			t.Cleanup(func() { assert.NoError(t, device.Close()) })
			if tc.closeFirst {
				require.NoError(t, device.Close())
			}
			for range tc.writes {
				n, err := device.Write(tc.packet)
				require.NoError(t, err)
				assert.Equal(t, len(tc.packet), n)
			}
			assert.Len(t, device.read, tc.expected)
			if tc.expected == 0 {
				return
			}
			buf := make([]byte, 64)
			n, err := device.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(tc.packet), n)
			if tc.packet[0]>>4 == 4 {
				assert.Equal(t, tc.packet[16:20], buf[12:16])
				assert.Equal(t, tc.packet[12:16], buf[16:20])
				assert.Equal(t, byte(0), buf[20])
			} else {
				assert.Equal(t, tc.packet[24:40], buf[8:24])
				assert.Equal(t, tc.packet[8:24], buf[24:40])
				assert.Equal(t, byte(129), buf[40])
			}
		})
	}
}

func TestDisabledTunClose(t *testing.T) {
	tests := []struct {
		name, description         string
		buffered, readers, closes int
		readAfterClose            bool
		expected                  int // packets read before EOF
	}{
		{name: "blocked_reader", description: "closing wakes an empty-queue reader with EOF", buffered: 0, readers: 1, closes: 1, expected: 0},
		{name: "multiple_readers", description: "all shared readers wake with EOF", buffered: 0, readers: 4, closes: 1, expected: 0},
		{name: "read_after_close", description: "a new read sees EOF rather than a nil-channel wait", buffered: 0, readers: 1, closes: 1, readAfterClose: true, expected: 0},
		{name: "buffered_drain", description: "accepted packets drain before EOF", buffered: 1, readers: 1, closes: 1, readAfterClose: true, expected: 1},
		{name: "repeated_close", description: "concurrent repeated closes are idempotent", buffered: 0, readers: 4, closes: 8, expected: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			synctest.Test(t, func(t *testing.T) {
				device := newDisabledTun(nil, 1, false, slog.New(slog.DiscardHandler))
				for range tc.buffered {
					device.read <- []byte{42}
				}
				type result struct {
					packets int
					err     error
					valid   bool
				}
				results := make(chan result, tc.readers)
				startReaders := func() {
					for range tc.readers {
						go func() {
							got := result{valid: true}
							buf := make([]byte, 1)
							for {
								n, err := device.Read(buf)
								if err != nil {
									got.err = err
									results <- got
									return
								}
								got.packets++
								got.valid = got.valid && n == 1 && buf[0] == 42
							}
						}()
					}
				}
				if !tc.readAfterClose {
					startReaders()
					synctest.Wait()
				}
				closed := make(chan error, tc.closes)
				for range tc.closes {
					go func() { closed <- device.Close() }()
				}
				for range tc.closes {
					require.NoError(t, <-closed)
				}
				if tc.readAfterClose {
					startReaders()
				}
				synctest.Wait()
				packets := 0
				for range tc.readers {
					select {
					case got := <-results:
						require.ErrorIs(t, got.err, io.EOF)
						assert.True(t, got.valid)
						packets += got.packets
					default:
						t.Fatal("reader did not finish after close")
					}
				}
				assert.Equal(t, tc.expected, packets)
			})
		})
	}
}

func TestDisabledTunConcurrentWriteClose(t *testing.T) {
	for _, tc := range []struct {
		name, description          string
		capacity, writers, closers int
		expected                   error // final read once writers and closers finish
	}{
		{name: "unbuffered", description: "writers and closers finish without a receiver", capacity: 0, writers: 4, closers: 4, expected: io.EOF},
		{name: "buffered", description: "writers cannot send on the channel while it closes", capacity: 1, writers: 8, closers: 8, expected: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			packet := disabledTunEchoPacket(t, false)
			for range 20 {
				device := newDisabledTun(nil, tc.capacity, false, slog.New(slog.DiscardHandler))
				start := make(chan struct{})
				results := make(chan error, tc.writers+tc.closers)
				var workers sync.WaitGroup
				for range tc.writers {
					workers.Go(func() {
						<-start
						for range 20 {
							_, err := device.Write(packet)
							if err != nil {
								results <- err
								return
							}
						}
						results <- nil
					})
				}
				for range tc.closers {
					workers.Go(func() { <-start; results <- device.Close() })
				}
				close(start)
				finished := make(chan struct{})
				go func() { workers.Wait(); close(finished) }()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Fatal("writers and closers did not finish")
				}
				close(results)
				for err := range results {
					require.NoError(t, err)
				}
				buf := make([]byte, len(packet))
				var err error
				for err == nil {
					_, err = device.Read(buf)
				}
				assert.ErrorIs(t, err, tc.expected)
			}
		})
	}
}

func TestDisabledTunQueueOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, description string
		queues            int
		expected          int // replies read through a wrapper
	}{
		{name: "single", description: "closing a queue wrapper leaves its device usable", queues: 1, expected: 1},
		{name: "shared", description: "closing all wrappers leaves the shared device usable", queues: 4, expected: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			device := newDisabledTun(nil, 1, false, slog.New(slog.DiscardHandler))
			t.Cleanup(func() { assert.NoError(t, device.Close()) })
			queues, err := device.Queues(tc.queues)
			require.NoError(t, err)
			for _, queue := range queues {
				require.NoError(t, queue.Close())
			}
			packet := disabledTunEchoPacket(t, false)
			n, err := queues[0].Write(packet)
			require.NoError(t, err)
			assert.Equal(t, len(packet), n)
			packets, err := queues[tc.queues-1].Read()
			require.NoError(t, err)
			require.Len(t, packets, tc.expected)
			assert.Equal(t, byte(0), packets[0].Bytes[20])
		})
	}
}

func BenchmarkDisabledTun(b *testing.B) {
	for _, tc := range []struct {
		name  string
		drain bool
	}{
		{"echo_round_trip", true}, {"full_queue_drop", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			device := newDisabledTun(nil, 1, false, slog.New(slog.DiscardHandler))
			b.Cleanup(func() { require.NoError(b, device.Close()) })
			packet := disabledTunEchoPacket(b, false)
			buf := make([]byte, len(packet))
			if !tc.drain {
				_, err := device.Write(packet)
				require.NoError(b, err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := device.Write(packet); err != nil {
					b.Fatal(err)
				}
				if tc.drain {
					if _, err := device.Read(buf); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
