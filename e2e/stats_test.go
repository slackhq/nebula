//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrometheusStats(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// Create a server with Prometheus stats enabled
	myControl, _, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{
		"stats": m{
			"type":      "prometheus",
			"listen":    "127.0.0.1:9090",
			"path":      "/metrics",
			"interval":  "1s",
			"namespace": "nebula",
			"subsystem": "e2e",
		},
	})

	// Start the server
	myControl.Start()
	defer myControl.Stop()

	// Fetch metrics from the Prometheus endpoint with context and retries
	ctx := t.Context()
	var resp *http.Response
	var body []byte

	// Retry fetching metrics for up to 3 seconds
	timeout := time.After(3 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

out:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("Context cancelled while waiting for metrics endpoint")
		case <-timeout:
			t.Fatal("Timeout waiting for metrics endpoint to become available")
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:9090/metrics", nil)
			if err != nil {
				continue
			}

			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil {
					break out
				}
			} else {
				resp.Body.Close()
			}
		}
	}

	metricsOutput := string(body)

	// Verify that some expected metrics are present
	assert.Contains(t, metricsOutput, "nebula_e2e_info", "Should contain version info metric")
	assert.Contains(t, metricsOutput, "nebula_e2e_handshake_manager", "Should contain handshake manager metrics")
	assert.Contains(t, metricsOutput, "nebula_e2e_firewall", "Should contain firewall metrics")

}

func TestGraphiteStats(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	ctx := t.Context()

	// expected metrics
	checks := map[string]string{
		"nebula.test.":           "Should contain configured prefix",
		"runtime.NumGoroutine":   "Should contain runtime metrics",
		"runtime.MemStats.Alloc": "Should contain memory stats",
	}

	// Create a mock Graphite server
	listener, err := net.Listen("tcp", "127.0.0.1:2003")
	require.NoError(t, err, "Failed to create mock Graphite listener")

	// Channel to signal goroutine completion
	done := make(chan struct{})

	// Channel to receive stats data
	statsChan := make(chan string, 1)

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Start accepting connections
	go func() {
		defer close(done)

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Context was cancelled, this is expected
				return
			}
			t.Logf("Accept error: %v", err)
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		seen := make(map[string]bool)
		var sb strings.Builder

		for scanner.Scan() {
			line := scanner.Text()
			sb.WriteString(line + "\n")
			for needle := range checks {
				if strings.Contains(line, needle) {
					seen[needle] = true
				}
			}
			// scan until we see all checks
			if len(seen) == len(checks) {
				break
			}
		}
		statsChan <- sb.String()
	}()

	// Ensure goroutine completes before test exits
	t.Cleanup(func() {
		listener.Close()
		<-done
	})

	// Create a server with Graphite stats configured
	myControl, _, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{
		"stats": m{
			"type":     "graphite",
			"protocol": "tcp",
			"host":     "127.0.0.1:2003",
			"interval": "1s",
			"prefix":   "nebula.test",
		},
	})

	// Start the server
	myControl.Start()
	defer myControl.Stop()

	// Wait for stats to be sent
	select {
	case statsData := <-statsChan:
		for needle, msg := range checks {
			// Check for expected metrics with the configured prefix
			assert.Contains(t, statsData, needle, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for stats to be sent to Graphite endpoint")
	}
}
