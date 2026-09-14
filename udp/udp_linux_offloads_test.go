//go:build linux && !android && !e2e_testing

package udp

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests pin the listen.udp_offloads=false behavior: no GSO/GRO probes,
// no cmsg scratch, and — critically — a still-functional send/receive path.
// The sockaddr name buffers are needed for every sendmmsg entry whether or
// not offloads are on, so prepareWriteMessages must allocate them even when
// it skips the cmsg slab (a nil name buffer panics in writeSockaddr on the
// first WriteBatch).

// TestPrepareWriteMessagesAlwaysAllocatesNames covers all four
// (offloadsEnabled, gsoSupported) combinations: the sockaddr name buffers
// must exist in every one, and the cmsg slab only when both are true.
// gsoSupported=false with offloads enabled is the old-kernel path where the
// UDP_SEGMENT probe fails — not just a config choice.
func TestPrepareWriteMessagesAlwaysAllocatesNames(t *testing.T) {
	cases := []struct {
		name     string
		offloads bool
		gso      bool
	}{
		{"offloads-off", false, false},
		{"offloads-on-probe-failed", true, false},
		{"offloads-off-gso-flag-set", false, true},
		{"offloads-on", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &batchWriter{fd: -1, isV4: true, l: testLogger()}
			w.gsoSupported = tc.gso
			w.prepareWriteMessages(MaxWriteBatch, tc.offloads)

			for i := range w.msgs {
				if len(w.names[i]) != unix.SizeofSockaddrInet6 {
					t.Fatalf("names[%d] len=%d, want %d", i, len(w.names[i]), unix.SizeofSockaddrInet6)
				}
				if w.msgs[i].Hdr.Name == nil {
					t.Fatalf("msgs[%d].Hdr.Name is nil", i)
				}
			}

			wantCmsg := tc.offloads && tc.gso
			if (w.cmsg != nil) != wantCmsg {
				t.Errorf("cmsg allocated = %v, want %v", w.cmsg != nil, wantCmsg)
			}
		})
	}
}

// TestWriteBatchOffloadsDisabledScripted drives WriteBatch through a
// batchWriter built with offloads disabled and a scripted sendFn: every
// packet must become its own sendmmsg entry (no GSO coalescing to plan),
// packed correctly despite the missing cmsg slab.
func TestWriteBatchOffloadsDisabledScripted(t *testing.T) {
	w := &batchWriter{fd: -1, isV4: true, l: testLogger()}
	w.prepareWriteMessages(MaxWriteBatch, false)

	var entryCounts []int
	w.sendFn = func(start, n int) (int, error) {
		entryCounts = append(entryCounts, n)
		return n, nil
	}

	// Same destination, equal sizes: prime coalescing bait that must not
	// coalesce with offloads off.
	dst := netip.MustParseAddrPort("127.0.0.1:4242")
	const numPkts = 4
	bufs := make([][]byte, numPkts)
	addrs := make([]netip.AddrPort, numPkts)
	for i := range bufs {
		bufs[i] = make([]byte, 1200)
		for j := range bufs[i] {
			bufs[i][j] = byte(i)
		}
		addrs[i] = dst
	}

	written, err := w.WriteBatch(bufs, addrs)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if written != numPkts {
		t.Errorf("written = %d, want %d", written, numPkts)
	}
	if len(entryCounts) != 1 || entryCounts[0] != numPkts {
		t.Errorf("sendmmsg entry counts = %v, want [%d]: packets must be one entry each", entryCounts, numPkts)
	}

	// Each prepared entry must carry exactly its own packet's bytes.
	got := capturePrepared(w, 0, numPkts)
	if len(got) != numPkts {
		t.Fatalf("prepared %d packets, want %d", len(got), numPkts)
	}
	for i, pkt := range got {
		if !slices.Equal(pkt, bufs[i]) {
			t.Errorf("entry %d bytes differ from bufs[%d]", i, i)
		}
	}
}

// TestOffloadsDisabledOnLoopback is the offloads-off smoke test, the mirror
// of TestGSOEngagesOnLoopback: a real socket built with Offloads=false must
// skip the GSO/GRO probes entirely (even on kernels that support them) and
// still deliver a same-destination batch as plain per-packet datagrams.
func TestOffloadsDisabledOnLoopback(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	defer rx.Close()
	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()

	udpSettings := Settings{
		Listen:   netip.MustParseAddrPort("127.0.0.1:0"),
		Multi:    false,
		Batch:    8, // batch > 1 would enable GRO if Offloads did not gate it
		Offloads: false,
	}
	uc, err := NewListener(testLogger(), udpSettings)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := uc.(*StdConn)
	defer sc.Close()

	if sc.bw.gsoSupported {
		t.Error("gsoSupported true with offloads disabled: probe was not skipped")
	}
	if sc.bw.cmsg != nil {
		t.Error("cmsg slab allocated with offloads disabled")
	}
	if sc.groSupported {
		t.Error("groSupported true with offloads disabled: probe was not skipped")
	}

	var entryCounts []int
	real := sc.bw.sendFn
	sc.bw.sendFn = func(start, n int) (int, error) {
		entryCounts = append(entryCounts, n)
		return real(start, n)
	}

	const numPkts = 8
	const pktLen = 1200
	bufs := make([][]byte, numPkts)
	addrs := make([]netip.AddrPort, numPkts)
	for i := range bufs {
		bufs[i] = make([]byte, pktLen)
		for j := range bufs[i] {
			bufs[i][j] = byte(i)
		}
		addrs[i] = dst
	}

	written, err := sc.WriteBatch(bufs, addrs)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if written != numPkts {
		t.Fatalf("written = %d, want %d", written, numPkts)
	}
	// One sendmmsg call with one entry per packet: a single-entry call here
	// means GSO engaged despite being disabled.
	if len(entryCounts) != 1 || entryCounts[0] != numPkts {
		t.Fatalf("sendmmsg entry counts = %v, want [%d]", entryCounts, numPkts)
	}

	_ = rx.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, pktLen+1)
	for i := range numPkts {
		n, _, err := rx.ReadFromUDP(got)
		if err != nil {
			t.Fatalf("rx read %d: %v", i, err)
		}
		if n != pktLen {
			t.Fatalf("rx read %d: len=%d want %d", i, n, pktLen)
		}
		for j := range n {
			if got[j] != byte(i) {
				t.Fatalf("rx read %d: byte %d = %#x, want %#x", i, j, got[j], byte(i))
			}
		}
	}
}

// TestOffloadsDisabledRxDelivers exercises the receive path with GRO gated
// off but batch reads still on: ListenOut must deliver plain datagrams via
// the MTU-sized buffer layout (no cmsg slots).
func TestOffloadsDisabledRxDelivers(t *testing.T) {
	udpSettings := Settings{
		Listen:   netip.MustParseAddrPort("127.0.0.1:0"),
		Multi:    false,
		Batch:    8,
		Offloads: false,
	}
	uc, err := NewListener(testLogger(), udpSettings)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := uc.(*StdConn)

	addr, err := sc.LocalAddr()
	if err != nil {
		t.Fatalf("LocalAddr: %v", err)
	}

	type rxPkt struct {
		from    netip.AddrPort
		payload []byte
	}
	rxCh := make(chan rxPkt, 16)
	listenDone := make(chan struct{})
	go func() {
		defer close(listenDone)
		_ = sc.ListenOut(func(from netip.AddrPort, payload []byte) {
			// payload aliases the shared recv buffer row; copy before handing off.
			rxCh <- rxPkt{from, slices.Clone(payload)}
		}, func() {})
	}()

	tx, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatalf("dial tx: %v", err)
	}
	defer tx.Close()

	want := [][]byte{
		[]byte("one"),
		make([]byte, 1200),
		make([]byte, 9000), // near-MTU datagram must fit the non-GRO buffer size
	}
	for i := range want[1] {
		want[1][i] = 0xAB
	}
	for i := range want[2] {
		want[2][i] = 0xCD
	}
	for i, p := range want {
		if _, err := tx.Write(p); err != nil {
			t.Fatalf("tx write %d: %v", i, err)
		}
	}

	for i, p := range want {
		select {
		case got := <-rxCh:
			if !slices.Equal(got.payload, p) {
				t.Errorf("packet %d: payload differs (len=%d want %d)", i, len(got.payload), len(p))
			}
			if got.from.Port() != tx.LocalAddr().(*net.UDPAddr).AddrPort().Port() {
				t.Errorf("packet %d: from=%v, want sender port %d", i, got.from, tx.LocalAddr().(*net.UDPAddr).Port)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}

	if err := sc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-listenDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ListenOut did not return after Close")
	}
}
