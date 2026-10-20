package nebula

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
)

// infoAPIServer is a small http+json listener on a unix socket that lets other
// programs on this machine resolve a vpn address to its certificate identity (name, groups, networks)
// for making authorization decisions. Lifecycle works like statsServer: the constructor wires the
// reload callback, reload records config, Start runs the runtime, Stop tears it down
type infoAPIServer struct {
	l       *slog.Logger
	ctx     context.Context
	hostMap *HostMap
	pki     *PKI

	// enabled mirrors `info_api.enabled` so callers of Start don't need to know the gating rules
	enabled atomic.Bool

	runMu  sync.Mutex
	runCfg *infoAPIConfig
	run    *infoAPIRuntime // non-nil while a runtime is live
}

// infoAPIRuntime is the live state owned by a single Start invocation. Stop and Start's exit path
// use pointer equality to tell "my runtime" apart from one that replaced it after a reload
type infoAPIRuntime struct {
	server   *http.Server
	listener net.Listener
}

// infoAPIConfig is a snapshot of the info_api config section, comparable with == so reload can
// detect "no change" cheaply
type infoAPIConfig struct {
	enabled bool
	listen  string // raw config value, for error messages
	addr    string // unix socket path
	// file mode applied to the unix socket after bind
	socketMode fs.FileMode
}

// newInfoAPIServerFromConfig builds a infoAPIServer and applies the initial config. The reload
// callback is registered first so a SIGHUP can later enable, fix, or disable the listener even if
// the initial config was bad. Nothing binds until Start, so config tests are side effect free.
// A bad config is logged rather than returned: it must not stop nebula from starting, the feature
// just stays disabled until a reload provides a valid config
func newInfoAPIServerFromConfig(ctx context.Context, l *slog.Logger, pki *PKI, hostMap *HostMap, c *config.C) *infoAPIServer {
	h := &infoAPIServer{
		l:       l,
		ctx:     ctx,
		hostMap: hostMap,
		pki:     pki,
	}

	c.RegisterReloadCallback(func(c *config.C) {
		if err := h.reload(c, false); err != nil {
			h.l.Warn("Failed to reload info API from config", "error", err)
		}
	})

	if err := h.reload(c, true); err != nil {
		h.l.Warn("Failed to apply info API config; it will stay disabled until the config is fixed and reloaded", "error", err)
	}
	return h
}

// reload records the latest config. The initial call only records it, Control.Start launches the
// first runtime via infoAPIStart. Later calls reconcile the running listener with the new config:
// enable, disable, or restart when the listen config changed
func (h *infoAPIServer) reload(c *config.C, initial bool) error {
	newCfg, err := loadInfoAPIConfig(c)
	if err != nil {
		return err
	}

	h.runMu.Lock()
	sameCfg := h.runCfg != nil && *h.runCfg == newCfg
	h.runCfg = &newCfg
	running := h.run != nil
	h.runMu.Unlock()

	h.enabled.Store(newCfg.enabled)

	if initial || sameCfg {
		return nil
	}

	if running {
		h.Stop()
	}
	if newCfg.enabled {
		go h.Start()
	}
	return nil
}

// Start binds the listener from the latest config and serves until Stop is called or ctx fires.
// Safe to call when disabled or already running (both no-op)
func (h *infoAPIServer) Start() {
	if !h.enabled.Load() {
		return
	}

	h.runMu.Lock()
	if h.ctx.Err() != nil || h.run != nil || h.runCfg == nil {
		h.runMu.Unlock()
		return
	}
	cfg := *h.runCfg
	ln, err := h.listen(cfg)
	if err != nil {
		// drop the cached config so a SIGHUP with the same config retries the bind
		h.runCfg = nil
		h.runMu.Unlock()
		h.l.Error("Failed to start info API listener", "listen", cfg.listen, "error", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/host", h.handleHost)
	mux.HandleFunc("GET /v1/self", h.handleSelf)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	rt := &infoAPIRuntime{server: srv, listener: ln}
	h.run = rt
	h.runMu.Unlock()

	h.l.Info("Starting info API listener", "addr", ln.Addr())
	cleanExit := h.serve(srv, ln)

	// A Stop that raced our bind shut the server down before Serve could adopt the listener;
	// closing it again is harmless and guarantees a unix socket file gets unlinked
	_ = ln.Close()

	// Clear our runtime only if nothing has replaced it. Stop races through here too but leaves
	// h.run == nil, so the pointer check skips
	h.runMu.Lock()
	if h.run == rt {
		h.run = nil
		// an error exit leaves runCfg cached as if it were applied, drop it so a SIGHUP with the
		// same config re-triggers Start once the user fixes the underlying problem
		if !cleanExit {
			h.runCfg = nil
		}
	}
	h.runMu.Unlock()
}

// serve runs srv.Serve and ensures ctx cancellation unblocks it. Returns true if the listener
// exited cleanly (Stop, ctx cancellation), false on an unexpected error
func (h *infoAPIServer) serve(srv *http.Server, ln net.Listener) bool {
	// ctx cancellation triggers a server shutdown which in turn unblocks Serve, closing `done` on
	// exit keeps the watcher from outliving this call
	done := make(chan struct{})
	go func() {
		select {
		case <-h.ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				h.l.Warn("Failed to shut down info API listener", "error", err)
			}
		case <-done:
		}
	}()
	defer close(done)

	err := srv.Serve(ln)
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return true
	}
	h.l.Error("Info API listener exited", "error", err)
	return false
}

// Stop tears down the active runtime, if any. Idempotent
func (h *infoAPIServer) Stop() {
	h.runMu.Lock()
	rt := h.run
	h.run = nil
	h.runMu.Unlock()
	if rt == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.server.Shutdown(shutdownCtx); err != nil {
		h.l.Warn("Failed to shut down info API listener", "error", err)
	}
}

// listen binds the configured unix socket. It also clears a stale socket file left by an unclean
// exit and applies the configured file mode
func (h *infoAPIServer) listen(cfg infoAPIConfig) (net.Listener, error) {
	if fi, err := os.Stat(cfg.addr); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("info_api.listen path %s exists and is not a socket, refusing to replace it", cfg.addr)
		}
		// a normal shutdown unlinks the socket, so a file here means a previous process exited
		// uncleanly, remove it so the bind below can succeed
		if err = os.Remove(cfg.addr); err != nil {
			return nil, fmt.Errorf("failed to remove stale socket %s: %w", cfg.addr, err)
		}
	}

	ln, err := net.Listen("unix", cfg.addr)
	if err != nil {
		return nil, err
	}
	// The socket is briefly live with umask-derived permissions before this chmod lands, tolerated
	// because connections accepted in that window still only reach this read-only API
	if err = os.Chmod(cfg.addr, cfg.socketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to set mode on socket %s: %w", cfg.addr, err)
	}
	return ln, nil
}

func (h *infoAPIServer) certState() *CertState {
	if h.pki == nil {
		return nil
	}
	return h.pki.getCertState()
}

// handleHost serves GET /v1/host?addr=<vpn addr>, answering with the identity of the host that
// owns the address: a peer with an active tunnel, or this node itself. addr may include a port,
// which is ignored, so clients can pass a connection's remote address through without parsing it
func (h *infoAPIServer) handleHost(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("addr")
	if q == "" {
		writeJSONError(w, http.StatusBadRequest, "missing addr parameter")
		return
	}
	ip, err := parseQueryAddrParam(q)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid address")
		return
	}

	crt := findCertificateForVpnAddr(h.certState(), h.hostMap, ip)
	if crt == nil {
		writeJSONError(w, http.StatusNotFound, "no active tunnel for address")
		return
	}
	h.writeHostIdentity(w, crt)
}

// handleSelf serves GET /v1/self, answering with this node's own identity
func (h *infoAPIServer) handleSelf(w http.ResponseWriter, r *http.Request) {
	var crt cert.Certificate
	if cs := h.certState(); cs != nil {
		crt = cs.getCertificate(cs.initiatingVersion)
	}
	if crt == nil {
		writeJSONError(w, http.StatusInternalServerError, "no certificate available")
		return
	}
	h.writeHostIdentity(w, crt)
}

func (h *infoAPIServer) writeHostIdentity(w http.ResponseWriter, crt cert.Certificate) {
	id, err := newHostIdentity(crt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to fingerprint certificate")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(id); err != nil {
		h.l.Debug("Failed to write info API response", "error", err)
	}
}

// findCertificateForVpnAddr answers "who owns this vpn address": ourselves (from local cert state,
// the hostmap never carries an entry for this node) or a peer with an active tunnel. Returns nil
// when the address is unknown or the tunnel is mid-teardown
func findCertificateForVpnAddr(cs *CertState, hostMap *HostMap, ip netip.Addr) cert.Certificate {
	if cs != nil && cs.myVpnAddrsTable != nil && cs.myVpnAddrsTable.Contains(ip) {
		return cs.getCertificate(cs.initiatingVersion)
	}

	hostinfo := hostMap.QueryVpnAddr(ip)
	if hostinfo == nil {
		return nil
	}
	cc := hostinfo.GetCert()
	if cc == nil {
		return nil
	}
	return cc.Certificate
}

// hostIdentity is the json document served for both /v1/host and /v1/self, every field is derived
// from the authenticated certificate alone
type hostIdentity struct {
	Name           string         `json:"name"`
	VpnAddrs       []netip.Addr   `json:"vpnAddrs"`
	Networks       []netip.Prefix `json:"networks"`
	UnsafeNetworks []netip.Prefix `json:"unsafeNetworks"`
	Groups         []string       `json:"groups"`
	Fingerprint    string         `json:"fingerprint"`
	Issuer         string         `json:"issuer"`
	NotBefore      time.Time      `json:"notBefore"`
	NotAfter       time.Time      `json:"notAfter"`
	CertVersion    int            `json:"certVersion"`
}

func newHostIdentity(crt cert.Certificate) (hostIdentity, error) {
	fp, err := crt.Fingerprint()
	if err != nil {
		return hostIdentity{}, err
	}

	// slices are always allocated so they marshal as [] rather than null
	networks := crt.Networks()
	id := hostIdentity{
		Name:           crt.Name(),
		VpnAddrs:       make([]netip.Addr, 0, len(networks)),
		Networks:       append(make([]netip.Prefix, 0, len(networks)), networks...),
		UnsafeNetworks: append(make([]netip.Prefix, 0, len(crt.UnsafeNetworks())), crt.UnsafeNetworks()...),
		Groups:         append(make([]string, 0, len(crt.Groups())), crt.Groups()...),
		Fingerprint:    fp,
		Issuer:         crt.Issuer(),
		NotBefore:      crt.NotBefore(),
		NotAfter:       crt.NotAfter(),
		CertVersion:    int(crt.Version()),
	}
	for _, n := range networks {
		id.VpnAddrs = append(id.VpnAddrs, n.Addr())
	}
	return id, nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// parseQueryAddrParam parses the addr query parameter, accepting a bare address or an address with
// a port (`192.168.100.7:54321`, `[fd00::1]:443`) so callers can pass a connection's RemoteAddr
// straight through. The result is unmapped, 4in6 addresses (::ffff:a.b.c.d) become ipv4
func parseQueryAddrParam(s string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap(), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

func loadInfoAPIConfig(c *config.C) (infoAPIConfig, error) {
	cfg := infoAPIConfig{
		enabled: c.GetBool("info_api.enabled", false),
		listen:  c.GetString("info_api.listen", ""),
	}
	if !cfg.enabled {
		return cfg, nil
	}

	if cfg.listen == "" {
		return cfg, errors.New("info_api.listen can not be empty when info_api is enabled")
	}
	addr, err := parseInfoAPIListen(cfg.listen)
	if err != nil {
		return cfg, err
	}
	cfg.addr = addr

	// read as a string so yaml can't reinterpret the octal literal
	modeStr := c.GetString("info_api.socket_mode", "0600")
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil || fs.FileMode(mode)&^fs.ModePerm != 0 {
		return cfg, fmt.Errorf("info_api.socket_mode was not a valid octal file mode: %s", modeStr)
	}
	cfg.socketMode = fs.FileMode(mode)
	return cfg, nil
}

// parseInfoAPIListen extracts the unix socket path from the info_api.listen config value, which
// must be a `unix://` URL with an absolute path, e.g. `unix:///var/run/nebula.sock`
func parseInfoAPIListen(listen string) (addr string, err error) {
	path, ok := strings.CutPrefix(listen, "unix://")
	if !ok {
		return "", fmt.Errorf("info_api.listen must be a unix:// socket path: %s", listen)
	} else if !filepath.IsAbs(path) {
		return "", fmt.Errorf("info_api.listen unix socket path must be absolute: %s", listen)
	}
	return path, nil
}
