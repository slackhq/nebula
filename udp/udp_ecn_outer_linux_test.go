//go:build linux && !android && !e2e_testing

package udp

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPlanRunBreaksOnECNChange confirms that two same-destination, same-size
// packets with different outer ECN end up in separate sendmmsg entries (the
// kernel stamps one outer codepoint per entry, so a run that straddled the
// boundary would silently lose information).
func TestPlanRunBreaksOnECNChange(t *testing.T) {
	u := &batchWriter{gsoSupported: true, maxGSOSegments: 63}
	dst := netip.MustParseAddrPort("10.0.0.1:4242")

	bufs := [][]byte{
		make([]byte, 1200),
		make([]byte, 1200),
		make([]byte, 1200),
	}
	addrs := []netip.AddrPort{dst, dst, dst}

	t.Run("uniform_ecn_runs_together", func(t *testing.T) {
		ecns := []byte{0x02, 0x02, 0x02}
		runLen, segSize := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 3 {
			t.Errorf("runLen=%d want 3 (uniform ECT(0))", runLen)
		}
		if segSize != 1200 {
			t.Errorf("segSize=%d want 1200", segSize)
		}
	})

	t.Run("ecn_change_truncates_run", func(t *testing.T) {
		// 0,0,3: first two run together, CE seeds a fresh entry.
		ecns := []byte{0x00, 0x00, 0x03}
		runLen, _ := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 2 {
			t.Errorf("runLen=%d want 2 (ECN changes at index 2)", runLen)
		}
	})

	t.Run("nil_ecns_runs_full", func(t *testing.T) {
		runLen, _ := u.planRun(bufs, addrs, nil, 0, 64)
		if runLen != 3 {
			t.Errorf("runLen=%d want 3 (nil ecns means no break)", runLen)
		}
	})

	t.Run("first_ecn_is_singleton", func(t *testing.T) {
		// Second packet has different ECN from the first → run halts at 1
		// (the first packet alone forms the run).
		ecns := []byte{0x00, 0x03, 0x03}
		runLen, _ := u.planRun(bufs, addrs, ecns, 0, 64)
		if runLen != 1 {
			t.Errorf("runLen=%d want 1 (different ECN immediately)", runLen)
		}
	})
}

// ecnReceiver is a raw UDP socket with IP_RECVTOS / IPV6_RECVTCLASS enabled,
// used to observe the outer ECN codepoint WriteTo stamps on the wire.
type ecnReceiver struct {
	fd   int
	addr netip.AddrPort
}

func newEcnReceiver(t *testing.T, v6 bool) *ecnReceiver {
	t.Helper()
	family := unix.AF_INET
	if v6 {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	var bindAddr netip.Addr
	if v6 {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1); err != nil {
			t.Fatalf("IPV6_RECVTCLASS: %v", err)
		}
		if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: [16]byte{15: 1}}); err != nil {
			t.Fatalf("bind ::1: %v", err)
		}
		bindAddr = netip.MustParseAddr("::1")
	} else {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTOS, 1); err != nil {
			t.Fatalf("IP_RECVTOS: %v", err)
		}
		if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatalf("bind 127.0.0.1: %v", err)
		}
		bindAddr = netip.MustParseAddr("127.0.0.1")
	}
	tv := unix.Timeval{Sec: 5}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	var port int
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		port = v.Port
	case *unix.SockaddrInet6:
		port = v.Port
	default:
		t.Fatalf("unexpected sockaddr %T", sa)
	}
	return &ecnReceiver{fd: fd, addr: netip.AddrPortFrom(bindAddr, uint16(port))}
}

// recvECN receives one datagram and returns the 2-bit ECN codepoint from its
// TOS / TCLASS cmsg.
func (r *ecnReceiver) recvECN(t *testing.T) byte {
	t.Helper()
	buf := make([]byte, 128)
	oob := make([]byte, 128)
	_, oobn, _, _, err := unix.Recvmsg(r.fd, buf, oob, 0)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatalf("parse cmsg: %v", err)
	}
	for _, m := range cmsgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS:
			return m.Data[0] & 0x03
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_TCLASS:
			return byte(binary.NativeEndian.Uint32(m.Data)) & 0x03
		}
	}
	t.Fatal("no TOS/TCLASS cmsg received")
	return 0
}

// TestWriteToStampsOuterECN sends single packets through StdConn.WriteTo and
// asserts the requested ECN codepoint lands on the outer IP header, for a
// v4 socket, a v6 socket, and the dual-stack case where a v4-mapped
// destination must be stamped via IP_TOS rather than IPV6_TCLASS.
func TestWriteToStampsOuterECN(t *testing.T) {
	cases := []struct {
		name    string
		bind    string
		recvV6  bool
		sendECN byte
	}{
		{"v4_socket_to_v4", "127.0.0.1", false, 0x03},
		{"v6_socket_to_v6", "::1", true, 0x01},
		{"dualstack_v6_socket_to_v4_mapped", "::", false, 0x02},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewListener(testLogger(), netip.MustParseAddr(tc.bind), 0, false, 8)
			if err != nil {
				t.Fatalf("NewListener: %v", err)
			}
			defer c.Close()
			rx := newEcnReceiver(t, tc.recvV6)

			if err = c.WriteTo([]byte("ecn"), rx.addr, tc.sendECN); err != nil {
				t.Fatalf("WriteTo(ecn=%#02x): %v", tc.sendECN, err)
			}
			if got := rx.recvECN(t); got != tc.sendECN {
				t.Errorf("outer ECN = %#02x, want %#02x", got, tc.sendECN)
			}

			// The zero codepoint sends no TOS cmsg and must arrive Not-ECT
			// (the socket-default TOS byte).
			if err = c.WriteTo([]byte("ecn"), rx.addr, 0); err != nil {
				t.Fatalf("WriteTo(ecn=0): %v", err)
			}
			if got := rx.recvECN(t); got != 0 {
				t.Errorf("outer ECN = %#02x, want 0 (Not-ECT)", got)
			}
		})
	}
}
