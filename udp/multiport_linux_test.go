//go:build linux && !android && !e2e_testing

package udp

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
)

// TestSendOnlyRecvBuffer checks a send only socket keeps the minimum receive buffer, even when listen.read_buffer
// is set, while listen.write_buffer still applies.
func TestSendOnlyRecvBuffer(t *testing.T) {
	c, err := NewListener(testLogger(), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1, SendOnly: true})
	if err != nil {
		t.Skipf("NewListener: %v", err)
	}
	sc := c.(*StdConn)
	defer sc.Close()

	minBuf, err := sc.GetRecvBuffer()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// The kernel minimum is a few KB, well below any default rmem
	if minBuf > 16<<10 {
		t.Fatalf("send only receive buffer is %d, want the kernel minimum", minBuf)
	}

	cfg := config.NewC(testLogger())
	cfg.Settings["listen"] = map[string]any{"read_buffer": 1 << 20, "write_buffer": 1 << 20}
	sc.ReloadConfig(cfg, nil)

	if got, err := sc.GetRecvBuffer(); err != nil || got != minBuf {
		t.Errorf("receive buffer after reload = %d, %v, want %d", got, err, minBuf)
	}
	if got, err := sc.GetSendBuffer(); err != nil || got < 1<<20 {
		t.Errorf("send buffer after reload = %d, %v, want at least %d", got, err, 1<<20)
	}
}

// TestSendOnlyReloadLogLevel checks a send only socket on sendOnlyLogger logs its reload outcomes at debug, there can
// be thousands
func TestSendOnlyReloadLogLevel(t *testing.T) {
	sysMax := readSysctlInt(t, "/proc/sys/net/core/wmem_max")
	for _, size := range []int{64 * 1024, sysMax + 1<<20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var buf bytes.Buffer
			l := sendOnlyLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			c, err := NewListener(l, Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1, SendOnly: true})
			if err != nil {
				t.Skipf("NewListener: %v", err)
			}
			defer c.Close()

			cfg := config.NewC(l)
			if err := cfg.LoadString(fmt.Sprintf("listen:\n  read_buffer: %d\n  write_buffer: %d\n", size, size)); err != nil {
				t.Fatal(err)
			}
			buf.Reset()
			c.ReloadConfig(cfg, nil)
			out := buf.String()
			if !strings.Contains(out, "level=DEBUG msg=\"listen.write_buffer was") {
				t.Errorf("missing debug write_buffer log in:\n%s", out)
			}
			if strings.Contains(out, "read_buffer") {
				t.Errorf("send only socket logged read_buffer:\n%s", out)
			}
			for _, level := range []string{"level=INFO", "level=WARN", "level=ERROR"} {
				if strings.Contains(out, level) {
					t.Errorf("unexpected %s log:\n%s", level, out)
				}
			}
		})
	}
}

// TestSendOnlyGSOLogLevel checks a send only socket on sendOnlyLogger logs its GSO probe at debug, the main listener
// reports it
func TestSendOnlyGSOLogLevel(t *testing.T) {
	for _, sendOnly := range []bool{false, true} {
		t.Run(strconv.FormatBool(sendOnly), func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			if sendOnly {
				l = sendOnlyLogger(l)
			}
			c, err := NewListener(l, Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Batch: 1, Offloads: true, SendOnly: sendOnly})
			if err != nil {
				t.Skipf("NewListener: %v", err)
			}
			defer c.Close()

			out := buf.String()
			if !strings.Contains(out, "msg=\"udp: GSO") {
				t.Fatalf("no GSO probe log in:\n%s", out)
			}
			quiet := !strings.Contains(out, "level=INFO") && !strings.Contains(out, "level=WARN")
			if quiet != sendOnly {
				t.Errorf("sendOnly=%v but probe logs were:\n%s", sendOnly, out)
			}
		})
	}
}
