//go:build !e2e_testing

package udp

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A burst larger than recvBatch arrives whole, with each datagram's own bytes and source address, and
// flush runs once per recvmsg_x batch rather than once per datagram.
func TestListenOutBatchesBurst(t *testing.T) {
	for _, tc := range []struct{ name, listen string }{
		{"v4", "127.0.0.1"},
		{"v6", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.AddrPortFrom(netip.MustParseAddr(tc.listen), 0)})
			require.NoError(t, err)
			la, err := c.LocalAddr()
			require.NoError(t, err)

			tx, err := net.Dial("udp", la.String())
			require.NoError(t, err)
			defer tx.Close()
			txAddr := netip.MustParseAddrPort(tx.LocalAddr().String())

			const total = recvBatch*3 + 7
			var mu sync.Mutex
			var got []string
			var froms []netip.AddrPort
			flushes := 0
			// Queued before the reader starts, so recvmsg_x sees full batches.
			for i := 0; i < total; i++ {
				_, err := tx.Write([]byte(fmt.Sprintf("pkt-%03d", i)))
				require.NoError(t, err)
			}

			done := make(chan struct{})
			go func() {
				_ = c.ListenOut(func(addr netip.AddrPort, payload []byte) {
					mu.Lock()
					got = append(got, string(payload))
					froms = append(froms, addr)
					mu.Unlock()
				}, func() {
					mu.Lock()
					flushes++
					mu.Unlock()
				})
				close(done)
			}()

			require.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				return len(got) == total
			}, 5*time.Second, 10*time.Millisecond)

			require.NoError(t, c.Close())
			<-done

			for i, p := range got {
				assert.Equal(t, fmt.Sprintf("pkt-%03d", i), p)
				assert.Equal(t, txAddr, froms[i])
			}
			assert.Equal(t, (total+recvBatch-1)/recvBatch, flushes)
		})
	}
}

// msghdrX round-trips through xnu's recvmsg_x on a loopback socket, v4 and v6. The kernel reads Name, Namelen,
// Iov and Iovlen from each entry and writes Namelen, Flags and Datalen back, so a field at the wrong offset or a
// wrong stride between entries shows up as a wrong length, sender, or payload.
// TestListenOutSingleFallback pins the path ListenOut takes when the kernel refuses recvmsg_x.
func TestListenOutSingleFallback(t *testing.T) {
	c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0")})
	require.NoError(t, err)
	la, err := c.LocalAddr()
	require.NoError(t, err)
	tx, err := net.Dial("udp", la.String())
	require.NoError(t, err)
	defer tx.Close()
	txAddr := netip.MustParseAddrPort(tx.LocalAddr().String())

	const total = 5
	for i := 0; i < total; i++ {
		_, err := tx.Write([]byte(fmt.Sprintf("pkt-%03d", i)))
		require.NoError(t, err)
	}

	var mu sync.Mutex
	var got []string
	flushes := 0
	done := make(chan struct{})
	go func() {
		_ = c.(*StdConn).listenOutSingle(func(addr netip.AddrPort, payload []byte) {
			assert.Equal(t, txAddr, addr)
			mu.Lock()
			got = append(got, string(payload))
			mu.Unlock()
		}, func() {
			mu.Lock()
			flushes++
			mu.Unlock()
		})
		close(done)
	}()

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == total
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, c.Close())
	<-done

	for i, p := range got {
		assert.Equal(t, fmt.Sprintf("pkt-%03d", i), p)
	}
	assert.Equal(t, total, flushes)
}

func TestCheckMsghdrX(t *testing.T) {
	valid := func() ([]msghdrX, []unix.RawSockaddrInet6) {
		hdrs := make([]msghdrX, 2)
		names := make([]unix.RawSockaddrInet6, 2)
		hdrs[0].Namelen, hdrs[0].Datalen = unix.SizeofSockaddrInet4, 1
		names[0].Family = unix.AF_INET
		hdrs[1].Namelen, hdrs[1].Datalen = unix.SizeofSockaddrInet6, MTU
		names[1].Family = unix.AF_INET6
		return hdrs, names
	}

	hdrs, names := valid()
	require.NoError(t, checkMsghdrX(hdrs, names, 2))
	require.NoError(t, checkMsghdrX(hdrs, names, 0))

	for _, tc := range []struct {
		name   string
		n      int
		mutate func([]msghdrX, []unix.RawSockaddrInet6)
	}{
		{"count past headers", 3, func([]msghdrX, []unix.RawSockaddrInet6) {}},
		{"datalen past buffer", 2, func(h []msghdrX, _ []unix.RawSockaddrInet6) { h[1].Datalen = MTU + 1 }},
		{"unknown family", 2, func(_ []msghdrX, a []unix.RawSockaddrInet6) { a[0].Family = unix.AF_UNIX }},
		{"family and length disagree", 2, func(h []msghdrX, _ []unix.RawSockaddrInet6) { h[0].Namelen = unix.SizeofSockaddrInet6 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdrs, names := valid()
			tc.mutate(hdrs, names)
			assert.Error(t, checkMsghdrX(hdrs, names, tc.n))
		})
	}
}

func TestMsghdrXKernelRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v6=%v", v6), func(t *testing.T) {
			// Loopback delivery goes through the dlil input thread, so the settle gives all three time to
			// queue and come back from one call, which is what exercises the stride.
			got := recvmsgXRoundTrip(t, v6, []int{1, 300, 1400}, 4, 50*time.Millisecond)
			assert.Equal(t, 3, got, "largest batch from one recvmsg_x call")
		})
	}
}

// Any burst, of any datagram lengths up to the kernel's maxdgram, into any number of headers, comes back in order
// with every entry's fields intact, and headers past the returned count untouched.
func FuzzMsghdrXKernelRoundTrip(f *testing.F) {
	f.Add(false, uint8(3), []byte{0, 1, 1, 44, 5, 120})
	f.Add(true, uint8(0), []byte{0, 0, 0x23, 0x29})           // one empty datagram, then one at MTU
	f.Add(false, uint8(1), []byte{0x23, 0x2a, 0x24, 0x00, 0}) // past MTU: cut to MTU, no MSG_TRUNC
	f.Add(true, uint8(recvBatch-1), bytes.Repeat([]byte{0x05, 0xdc}, recvBatch))

	f.Fuzz(func(t *testing.T, v6 bool, spare uint8, sizes []byte) {
		// Two bytes per datagram, big-endian, folded into [0, maxdgram].
		var lens []int
		for i := 0; i+1 < len(sizes) && len(lens) < recvBatch; i += 2 {
			lens = append(lens, (int(sizes[i])<<8|int(sizes[i+1]))%(maxDgram+1))
		}
		if len(lens) == 0 {
			return
		}
		recvmsgXRoundTrip(t, v6, lens, 1+int(spare)%recvBatch, time.Millisecond)
	})
}

// maxDgram is darwin's default net.inet.udp.maxdgram, the largest datagram a loopback sender may write.
const maxDgram = 9216

// recvmsgXRoundTrip sends one datagram per entry of lens to a fresh loopback socket, drains them with recvmsg_x
// into nh headers, and checks every field the kernel writes. Neighboring datagrams differ in sender, length and
// fill byte, so no field can pass by reading a neighbor's value. It returns the largest batch one call returned.
func recvmsgXRoundTrip(t *testing.T, v6 bool, lens []int, nh int, settle time.Duration) int {
	t.Helper()
	network, lo := "udp4", netip.MustParseAddr("127.0.0.1")
	if v6 {
		network, lo = "udp6", netip.IPv6Loopback()
	}
	rx, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo, 0)))
	require.NoError(t, err)
	defer rx.Close()

	txs := make([]*net.UDPConn, 3)
	for i := range txs {
		txs[i], err = net.DialUDP(network, nil, rx.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		defer txs[i].Close()
	}
	senders := make([]netip.AddrPort, len(lens))
	for i, l := range lens {
		tx := txs[i%len(txs)]
		senders[i] = tx.LocalAddr().(*net.UDPAddr).AddrPort()
		_, err := tx.Write(bytes.Repeat([]byte{byte(i + 1)}, l))
		require.NoError(t, err)
	}
	time.Sleep(settle)

	// Namelen goes in as the v6 size on both families, so the v4 size coming back proves the kernel wrote it.
	const sentinel = 0xa5a5a5a5a5a5a5a5
	wantNamelen := uint32(unix.SizeofSockaddrInet4)
	if v6 {
		wantNamelen = unix.SizeofSockaddrInet6
	}
	bufs := make([][]byte, nh)
	names := make([]unix.RawSockaddrInet6, nh)
	iovs := make([]unix.Iovec, nh)
	hdrs := make([]msghdrX, nh)
	for i := range hdrs {
		bufs[i] = make([]byte, MTU)
		iovs[i].Base = &bufs[i][0]
		iovs[i].SetLen(MTU)
	}

	// A datagram dropped on loopback would otherwise block rc.Read forever.
	require.NoError(t, rx.SetReadDeadline(time.Now().Add(5*time.Second)))
	rc, err := rx.SyscallConn()
	require.NoError(t, err)
	largest := 0
	for next := 0; next < len(lens); {
		for i := range hdrs {
			clear(bufs[i])
			hdrs[i] = msghdrX{
				Name:    (*byte)(unsafe.Pointer(&names[i])),
				Namelen: unix.SizeofSockaddrInet6,
				Iov:     &iovs[i],
				Iovlen:  1,
				Flags:   -1,
				Datalen: sentinel,
			}
		}
		var n int
		var errno syscall.Errno
		require.NoError(t, rc.Read(func(fd uintptr) bool {
			r0, _, e := unix.Syscall6(unix.SYS_RECVMSG_X, fd, uintptr(unsafe.Pointer(&hdrs[0])), uintptr(nh), 0, 0, 0)
			n, errno = int(r0), e
			return e != unix.EAGAIN
		}), "received %d of %d datagrams", next, len(lens))
		require.Zero(t, errno)
		require.Positive(t, n)
		require.LessOrEqual(t, n, min(nh, len(lens)-next))
		largest = max(largest, n)
		require.NoError(t, checkMsghdrX(hdrs[:nh], names[:nh], n), "ListenOut would fall back on this batch")

		for i := range n {
			d := next + i
			h := &hdrs[i]
			want := min(lens[d], MTU)
			require.EqualValues(t, want, h.Datalen, "datagram %d Datalen", d)
			require.Equal(t, wantNamelen, h.Namelen, "datagram %d Namelen", d)
			from, ok := sockaddrToAddrPort(&names[i])
			require.True(t, ok, "datagram %d family %d", d, names[i].Family)
			require.Equal(t, senders[d], from, "datagram %d sender", d)
			// Flags goes in as -1 and must come back 0. xnu's list receive (soreceive_m_list) never sets
			// MSG_TRUNC, so a datagram past MTU arrives silently cut to MTU, as recvfrom through net.UDPConn does.
			require.Zero(t, h.Flags, "datagram %d Flags", d)
			require.Equal(t, bytes.Repeat([]byte{byte(d + 1)}, want), bufs[i][:want], "datagram %d payload", d)
			if want < MTU {
				require.Zero(t, bufs[i][want], "datagram %d wrote past Datalen", d)
			}
		}
		for i := n; i < nh; i++ {
			require.EqualValues(t, uint64(sentinel), hdrs[i].Datalen, "spare header %d Datalen", i)
			require.EqualValues(t, unix.SizeofSockaddrInet6, hdrs[i].Namelen, "spare header %d Namelen", i)
		}
		next += n
	}
	return largest
}
