package sshd

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// waitAccept dials addr and confirms the server accepts a TCP connection.
func waitAccept(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not connect to %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startServer binds the requested addresses on ephemeral ports and returns the
// server plus the resolved concrete addresses Run is listening on.
func startServer(t *testing.T, addrs []string) (*SSHServer, []string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s, err := NewSSHServer(ctx, testLogger())
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}

	// Pre-bind to learn the ephemeral ports, then hand the concrete addresses
	// to Run so tests can dial them.
	resolved := make([]string, len(addrs))
	for i, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("probe listen %s: %v", a, err)
		}
		resolved[i] = ln.Addr().String()
		ln.Close()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Run(resolved); err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	}()
	t.Cleanup(func() {
		s.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Run did not return after Stop")
		}
	})

	for _, a := range resolved {
		waitAccept(t, a)
	}
	return s, resolved
}

// TestSSHServer_Run_MultipleListeners pins the bind-ALL behavior: every address
// in the slice accepts connections, and Stop closes all of them.
func TestSSHServer_Run_MultipleListeners(t *testing.T) {
	s, resolved := startServer(t, []string{"127.0.0.1:0", "[::1]:0"})

	for _, a := range resolved {
		waitAccept(t, a)
	}

	s.Stop()

	// After Stop every listener should be closed; a fresh dial must fail.
	deadline := time.Now().Add(2 * time.Second)
	for _, a := range resolved {
		for {
			conn, err := net.DialTimeout("tcp", a, 100*time.Millisecond)
			if err != nil {
				break
			}
			conn.Close()
			if time.Now().After(deadline) {
				t.Fatalf("listener %s still accepting after Stop", a)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestSSHServer_Run_SingleListener pins legacy single-address behavior.
func TestSSHServer_Run_SingleListener(t *testing.T) {
	_, resolved := startServer(t, []string{"127.0.0.1:0"})
	if len(resolved) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(resolved))
	}
	waitAccept(t, resolved[0])
}

// TestSSHServer_Run_BindFailureIsAllOrNothing verifies that if any address in
// the slice fails to bind, Run returns the error and leaves nothing listening.
func TestSSHServer_Run_BindFailureIsAllOrNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Occupy a port so the second bind in Run fails.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy listen: %v", err)
	}
	defer occupied.Close()
	occupiedAddr := occupied.Addr().String()

	// A free address that Run should bind first, then have to tear down.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	freeAddr := probe.Addr().String()
	probe.Close()

	s, err := NewSSHServer(ctx, testLogger())
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}

	if err := s.Run([]string{freeAddr, occupiedAddr}); err == nil {
		t.Fatal("expected Run to fail when an address cannot bind")
	}

	// The successfully-bound first address must have been closed on the failure
	// path, so it is available to bind again.
	ln, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Fatalf("first listener leaked (still bound): %v", err)
	}
	ln.Close()
}
