// Package rphttp is the build-tag-free transport layer shared by both
// the embedded rosenpass service (pq/rposvc) and the sidecar
// distributor (pq/rpsidecar). It provides:
//
//   - Discovery: a tiny HTTP server that hands out the local Rosenpass
//     static public key to peers reachable over the nebula tunnel.
//   - FetchPubkey: the client side that pulls a peer's pubkey from its
//     Discovery endpoint, with cert-bound hash verification.
//   - PeerObserved: the event nebula emits on every handshake completion,
//     carrying the peer identity plus the gossiped rosenpass routing info.
//
// Splitting these out of pq/rposvc lets the default (sidecar) build
// reuse the same HTTP plumbing without pulling in go-rosenpass.
package rphttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Discovery is a tiny TCP service that hands out the local Rosenpass
// static public key to peers reachable inside the nebula tunnel, plus
// a client that fetches a peer's pubkey on demand.
//
// Trust model: the fetch rides over the nebula tunnel, which is
// authenticated by nebula's CA-signed certificate exchange. An
// adversary that can break that authentication can also substitute
// the pubkey here. For HNDL (passive) threat models this is fine; for
// active CRQC adversaries, callers should additionally bind the
// expected pubkey hash via a nebula cert extension and reject any
// fetched bytes whose hash does not match.
//
// Wire format (very deliberately boring):
//
//	GET / HTTP/1.1
//	Host: <peer-nebula-ip>:51820
//	Accept: application/octet-stream
//
//	HTTP/1.1 200 OK
//	Content-Type: application/octet-stream
//	X-Rp-Pubkey-Sha256: <64-hex>
//
//	<raw rosenpass public key bytes>
//
// HTTP keeps it debuggable with curl. Bytes are public so plaintext
// is fine; the hash header lets a constrained client cheaply
// pre-validate before downloading the full ~524 KB body.
type Discovery struct {
	pubkey    []byte
	hashHex   string
	listener  net.Listener
	server    *http.Server
	closeOnce sync.Once

	// concurrentConns caps how many simultaneous TCP connections the
	// HTTP server will keep open. A peer (or off-tunnel attacker on
	// the wildcard-bound port) opening many idle/slow connections
	// would otherwise pin one goroutine per connection until
	// ReadTimeout (10s) elapses, exhausting goroutine + FD budget.
	concurrentConns chan struct{}
}

// NewDiscovery starts an HTTP server bound to addr that returns the
// supplied Rosenpass public key on every GET. Caller closes via
// Close.
func NewDiscovery(addr *net.TCPAddr, pubkey []byte) (*Discovery, error) {
	if len(pubkey) == 0 {
		return nil, errors.New("rphttp discovery: empty pubkey")
	}
	if addr == nil {
		return nil, errors.New("rphttp discovery: addr required")
	}
	sum := sha256.Sum256(pubkey)
	hashHex := hex.EncodeToString(sum[:])

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("rphttp discovery listen %s: %w", addr, err)
	}
	d := &Discovery{
		pubkey:          append([]byte(nil), pubkey...),
		hashHex:         hashHex,
		listener:        ln,
		concurrentConns: make(chan struct{}, 32),
	}
	// MaxBytesHandler caps any inbound request body at 4 KB. Our
	// handler only serves GET so a body shouldn't exist; the cap
	// stops a hostile (but cert-valid, since they're inside the
	// tunnel) peer from holding goroutines pinned with a slow-drip
	// multi-gigabyte body for the duration of ReadTimeout.
	d.server = &http.Server{
		Handler:           http.MaxBytesHandler(http.HandlerFunc(d.handle), 4096),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second, // enough for slow links serving 524 KB
		IdleTimeout:       30 * time.Second,
		// ConnState gates concurrent connections. New connections
		// that would exceed the cap are immediately closed; existing
		// idle connections are aged out by IdleTimeout.
		ConnState: d.connState,
	}
	go func() { _ = d.server.Serve(ln) }()
	return d, nil
}

// connState gates how many concurrent connections the server keeps
// open. We try to acquire a token in StateNew; if the bucket is
// full, the connection is closed before any request bytes are read.
// Tokens are released in StateClosed / StateHijacked. Idle / Active
// transitions are no-ops.
func (d *Discovery) connState(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		select {
		case d.concurrentConns <- struct{}{}:
		default:
			// Bucket full: refuse this connection.
			_ = c.Close()
		}
	case http.StateClosed, http.StateHijacked:
		select {
		case <-d.concurrentConns:
		default:
			// Token wasn't ours (we refused the connection); ok.
		}
	}
}

func (d *Discovery) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Rp-Pubkey-Sha256", d.hashHex)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(d.pubkey)))
	_, _ = w.Write(d.pubkey)
}

// Close stops accepting new connections and shuts down the server.
func (d *Discovery) Close() error {
	var err error
	d.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = d.server.Shutdown(ctx)
	})
	return err
}

// LocalAddr returns the bound TCP address. Useful for tests where
// the caller passed Port: 0.
func (d *Discovery) LocalAddr() *net.TCPAddr {
	return d.listener.Addr().(*net.TCPAddr)
}

// Fetcher is the function signature both rposvc.Coordinator and
// rpsidecar.Distributor accept for pubkey retrieval. Tests inject a
// stub; production code uses FetchPubkey.
type Fetcher func(ctx context.Context, addr *net.TCPAddr, expectedHash string, dialer *net.Dialer) ([]byte, error)

// FetchPubkey retrieves a peer's Rosenpass public key from
// http://addr/. If expectedHash is non-empty (lowercase hex SHA-256),
// the returned bytes must match or ErrPubkeyHashMismatch is returned.
//
// dialer is allowed to be nil; default uses an OS dialer with a 5s
// connect timeout. For tunnel-internal fetches over nebula, the
// connection naturally rides the encrypted tunnel because addr is on
// the nebula overlay subnet.
func FetchPubkey(ctx context.Context, addr *net.TCPAddr, expectedHash string, dialer *net.Dialer) ([]byte, error) {
	if addr == nil {
		return nil, errors.New("rphttp fetch: addr required")
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second}
	}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	// Refuse redirects: the discovery service is reached at a fixed
	// VPN address inside the tunnel; a peer responding with a 3xx
	// could trick the fetcher into pulling pubkey bytes from any
	// other underlay-reachable host, completely bypassing the
	// tunnel-authenticated trust model. The default Go redirect
	// policy follows up to 10 hops which is exactly the wrong
	// behaviour here.
	cli := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("http://%s/", addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap; mceliece460896 pubkey ~524 KB
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	sum := sha256.Sum256(body)
	gotHash := hex.EncodeToString(sum[:])
	if expectedHash != "" && gotHash != expectedHash {
		return nil, ErrPubkeyHashMismatch{Expected: expectedHash, Got: gotHash}
	}
	// Also verify against the server-asserted header as a sanity check.
	if h := resp.Header.Get("X-Rp-Pubkey-Sha256"); h != "" && h != gotHash {
		return nil, fmt.Errorf("body/header hash mismatch: header=%s body=%s", h, gotHash)
	}
	return body, nil
}

// ErrPubkeyHashMismatch reports a verified-fetch failure where the
// fetched pubkey did not match the expected fingerprint (e.g. from a
// nebula cert extension).
type ErrPubkeyHashMismatch struct {
	Expected string
	Got      string
}

func (e ErrPubkeyHashMismatch) Error() string {
	return fmt.Sprintf("rosenpass pubkey hash mismatch: expected %s got %s", e.Expected, e.Got)
}
