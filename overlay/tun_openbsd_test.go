//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"bytes"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTun_WriteFraming(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: w}

	for _, tc := range []struct {
		name string
		pkt  []byte
		af   byte
	}{
		// Literal families rather than syscall.AF_*, so a wrong constant in Write can't also fix the expectation.
		{"ipv4", []byte{0x45, 1, 2, 3, 4, 5}, 2},
		{"ipv6", []byte{0x60, 1, 2, 3, 4, 5}, 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tn.Write(tc.pkt)
			require.NoError(t, err)
			require.Equal(t, len(tc.pkt), n)

			got := make([]byte, 64)
			n, err = r.Read(got)
			require.NoError(t, err)
			require.Equal(t, append([]byte{0, 0, 0, tc.af}, tc.pkt...), got[:n])
		})
	}

	_, err = tn.Write([]byte{0x10, 1, 2, 3})
	require.Error(t, err)
	_, err = tn.Write([]byte{})
	require.ErrorIs(t, err, syscall.EIO)

	// The rejected writes must not have put anything on the fd, so the next read sees only this packet.
	pkt := []byte{0x45, 9, 9}
	_, err = tn.Write(pkt)
	require.NoError(t, err)
	got := make([]byte, 64)
	n, err := r.Read(got)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0, 0, 0, 2}, pkt...), got[:n])
}

func TestTun_ReadStripsHeader(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: r}

	pkt := []byte{0x45, 1, 2, 3, 4, 5}
	_, err = w.Write(append([]byte{0, 0, 0, syscall.AF_INET}, pkt...))
	require.NoError(t, err)

	got := make([]byte, 64)
	n, err := tn.Read(got)
	require.NoError(t, err)
	require.Equal(t, pkt, got[:n])
}

func TestTun_ReadShortAndEmpty(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: r}

	// Fewer bytes than the protocol header is not a packet.
	_, err = w.Write([]byte{0, 0})
	require.NoError(t, err)
	n, err := tn.Read(make([]byte, 64))
	require.NoError(t, err)
	require.Zero(t, n)

	// A zero length destination still consumes the header without panicking.
	_, err = w.Write([]byte{0, 0, 0, syscall.AF_INET})
	require.NoError(t, err)
	n, err = tn.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)

	// The next packet reads cleanly only if both calls above consumed exactly what was written.
	pkt := []byte{0x45, 1, 2, 3}
	_, err = w.Write(append([]byte{0, 0, 0, syscall.AF_INET}, pkt...))
	require.NoError(t, err)
	got := make([]byte, 64)
	n, err = tn.Read(got)
	require.NoError(t, err)
	require.Equal(t, pkt, got[:n])
}

// unix.Readv and unix.Writev leak the contents of the [][]byte they're handed, so a header that lives
// on Read's or Write's stack gets moved to the heap on every packet. This guards the layout that
// avoids that.
func TestTun_ReadWriteDoNotAllocate(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tw := &tun{f: w}
	tr := &tun{f: r}

	pkts := [][]byte{bytes.Repeat([]byte{0x45}, 1300), bytes.Repeat([]byte{0x60}, 1300)}
	buf := make([]byte, 1500)
	i := 0
	allocs := testing.AllocsPerRun(1000, func() {
		i++
		if _, err := tw.Write(pkts[i%len(pkts)]); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Read(buf); err != nil {
			t.Fatal(err)
		}
	})
	require.Zero(t, allocs)
}
