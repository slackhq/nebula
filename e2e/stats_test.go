//go:build e2e_testing
// +build e2e_testing

package e2e

import (
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

	// Fetch metrics from the Prometheus endpoint with context
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:9090/metrics", nil)
	require.NoError(t, err, "Failed to create request")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "Failed to fetch metrics endpoint")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Metrics endpoint should return 200 OK")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read metrics response")

	metricsOutput := string(body)

	// Verify that some expected metrics are present
	assert.Contains(t, metricsOutput, "nebula_e2e_info", "Should contain version info metric")
	assert.Contains(t, metricsOutput, "nebula_e2e_handshake_manager", "Should contain handshake manager metrics")
	assert.Contains(t, metricsOutput, "nebula_e2e_firewall", "Should contain firewall metrics")

}

func TestGraphiteStats(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	ctx := t.Context()

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

		// Read all data sent by the stats system
		data, err := io.ReadAll(conn)
		if err != nil {
			if ctx.Err() != nil {
				// Context was cancelled
				return
			}
			t.Logf("Read error: %v", err)
			return
		}

		statsChan <- string(data)
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
		// Verify the data is in Graphite plaintext format: "metric.path value timestamp\n"
		assert.NotEmpty(t, statsData, "Should receive stats data")

		// Check for expected metrics with the configured prefix
		assert.Contains(t, statsData, "nebula.test.", "Should contain configured prefix")
		assert.Contains(t, statsData, "runtime.NumGoroutine", "Should contain runtime metrics")
		assert.Contains(t, statsData, "runtime.MemStats.Alloc", "Should contain memory stats")

		// Verify format: each line should have metric, value, and timestamp
		lines := strings.Split(strings.TrimSpace(statsData), "\n")
		assert.Greater(t, len(lines), 0, "Should have at least one metric line")

		// Check first line format
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			assert.Equal(t, 3, len(parts), "Each metric line should have 3 parts: metric value timestamp")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for stats to be sent to Graphite endpoint")
	}
}
