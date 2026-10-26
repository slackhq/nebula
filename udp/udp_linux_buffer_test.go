//go:build linux && !android && !e2e_testing

package udp

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
)

func readSysctlInt(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("can't read %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Skipf("can't parse %s: %v", path, err)
	}
	return n
}

// TestSetBufferAboveSysctlMax asks for more than net.core.{r,w}mem_max. With
// CAP_NET_ADMIN the FORCE variant takes it as is; without it we must fall back
// to the plain option and get the clamped size instead of EPERM.
func TestSetBufferAboveSysctlMax(t *testing.T) {
	cases := []struct {
		name   string
		sysctl string
		set    func(*StdConn, int) error
		get    func(*StdConn) (int, error)
	}{
		{"read", "/proc/sys/net/core/rmem_max", (*StdConn).SetRecvBuffer, (*StdConn).GetRecvBuffer},
		{"write", "/proc/sys/net/core/wmem_max", (*StdConn).SetSendBuffer, (*StdConn).GetSendBuffer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sysMax := readSysctlInt(t, tc.sysctl)
			c, err := NewListener(testLogger(), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1})
			if err != nil {
				t.Skipf("NewListener: %v", err)
			}
			sc := c.(*StdConn)
			defer sc.Close()

			want := sysMax + 1<<20
			if err := tc.set(sc, want); err != nil {
				t.Fatalf("set %d: %v", want, err)
			}
			got, err := tc.get(sc)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			// The kernel doubles the value; either path gives at least the clamped size.
			if got < 2*sysMax {
				t.Fatalf("effective size %d, want >= %d", got, 2*sysMax)
			}
			t.Logf("requested %d, %s=%d, effective %d (forced=%v)", want, tc.sysctl, sysMax, got, got >= 2*want)
		})
	}
}

// TestReloadConfigBufferLogLevel checks that a clamped buffer is a Warn, and a
// buffer that fits is still the Info it always was.
func TestReloadConfigBufferLogLevel(t *testing.T) {
	sysMax := readSysctlInt(t, "/proc/sys/net/core/rmem_max")
	if wmax := readSysctlInt(t, "/proc/sys/net/core/wmem_max"); wmax < sysMax {
		sysMax = wmax
	}
	cases := []struct {
		name string
		size int
		want []string
	}{
		{"fits", 64 * 1024, []string{"level=INFO msg=\"listen.read_buffer was set\"", "level=INFO msg=\"listen.write_buffer was set\""}},
		{"too big", sysMax + 1<<20, []string{"level=WARN msg=\"listen.read_buffer was limited by the system\"", "level=WARN msg=\"listen.write_buffer was limited by the system\""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&buf, nil))
			c, err := NewListener(l, Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1})
			if err != nil {
				t.Skipf("NewListener: %v", err)
			}
			sc := c.(*StdConn)
			defer sc.Close()

			if tc.size > sysMax {
				// With CAP_NET_ADMIN the FORCE variant takes any size, nothing gets limited.
				if err := sc.SetRecvBuffer(tc.size); err == nil {
					if got, _ := sc.GetRecvBuffer(); got >= 2*tc.size {
						t.Skip("FORCE path took the full size, can't observe the limit")
					}
				}
			}

			cfg := config.NewC(l)
			if err := cfg.LoadString(fmt.Sprintf("listen:\n  read_buffer: %d\n  write_buffer: %d\n", tc.size, tc.size)); err != nil {
				t.Fatal(err)
			}
			buf.Reset()
			sc.ReloadConfig(cfg)
			out := buf.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %s in:\n%s", w, out)
				}
			}
			if strings.Contains(out, "level=ERROR") {
				t.Errorf("unexpected error log:\n%s", out)
			}
			t.Log(out)
		})
	}
}
