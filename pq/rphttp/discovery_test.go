package rphttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscovery_RoundTrip(t *testing.T) {
	pubkey := make([]byte, 1024)
	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	sum := sha256.Sum256(pubkey)
	expected := hex.EncodeToString(sum[:])

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	d, err := NewDiscovery(addr, pubkey)
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := FetchPubkey(ctx, d.LocalAddr(), expected, nil)
	require.NoError(t, err)
	assert.Equal(t, pubkey, got)
}

func TestDiscovery_HashMismatchRejected(t *testing.T) {
	pubkey := []byte("the real pubkey bytes go here")
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	d, err := NewDiscovery(addr, pubkey)
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = FetchPubkey(ctx, d.LocalAddr(), "deadbeef", nil)
	require.Error(t, err)
	_, ok := err.(ErrPubkeyHashMismatch)
	assert.True(t, ok, "expected ErrPubkeyHashMismatch, got %T", err)
}

func TestDiscovery_NoExpectedHashAccepts(t *testing.T) {
	pubkey := []byte("a public key")
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	d, err := NewDiscovery(addr, pubkey)
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := FetchPubkey(ctx, d.LocalAddr(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, pubkey, got)
}

func TestFetchPubkeyDoesNotLeakTransportGoroutines(t *testing.T) {
	body := bytes.Repeat([]byte{0xAB}, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	addr, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)

	// Burn a few calls so transport-pool init settles.
	for i := 0; i < 5; i++ {
		_, _ = FetchPubkey(context.Background(), addr, "", nil)
	}
	runtime.GC()
	base := runtime.NumGoroutine()

	const N = 200
	for i := 0; i < N; i++ {
		_, err := FetchPubkey(context.Background(), addr, "", nil)
		require.NoError(t, err)
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	require.LessOrEqualf(t, after, base+20,
		"FetchPubkey leaks goroutines: base=%d after=%d delta=%d", base, after, after-base)
}
