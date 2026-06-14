package pq

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileProvider is the canonical Provider for production deployments. It
// owns a directory of "<sha256-hex>.psk" files, where <sha256-hex> is
// the lowercase SHA-256 of the peer's static public key, and each file
// contains exactly 32 bytes.
//
// Optional binding-hint companion files (see bindingHintExt) may sit
// alongside the PSK file. Their contents are a single 64-char
// lowercase hex string (with optional trailing newline): the SHA-256
// of the provider pubkey the sidecar believes derived this PSK. Nebula
// uses that hash to cross-check the peer's CA-signed PQ-PSK binding
// cert extension during the handshake, catching a sidecar that's been
// re-keyed or compromised since the cert was issued. Absent or
// malformed binding-hint files leave the per-peer rpHash empty, which
// callers treat as "no binding info; defer to policy" — the PSK still
// loads either way.
//
// The directory is rescanned at construction and on filesystem events
// reported by fsnotify. Events are debounced (default 250ms quiet
// window) so that the tempfile-then-rename pattern used by PQ-PSK
// daemons doesn't trigger a half-loaded snapshot. A new snapshot
// replaces the old via atomic.Pointer; lookups never block on I/O.
type FileProvider struct {
	dir      string
	debounce time.Duration
	// health is the interval for the self-heal ticker: it periodically
	// re-stats the watched dir, retries the fsnotify watch when it has
	// been lost (dir removed/renamed), and does a fallback rescan so the
	// provider recovers without depending on a fresh fsnotify event.
	// Defaults to defaultHealthInterval; never zero once constructed.
	health time.Duration
	// staleWarnAfter, when non-zero, is how long the snapshot may go
	// without a content change before the health ticker logs a Warn
	// (once per stale episode). Zero disables the warning — correct for
	// statically-provisioned PSK directories that legitimately never
	// rotate. The snapshot-age gauge updates regardless.
	staleWarnAfter time.Duration
	l              *slog.Logger

	entries atomic.Pointer[map[string]fileEntry]
	// lastChange is the unix-nano timestamp of the last rescan whose
	// snapshot CONTENT differed from the previous one (not merely the
	// last successful rescan — health-tick rescans of an unchanged dir
	// must not reset it, or a dead rotating sidecar would never look
	// stale). Read by the health ticker for the age gauge + stale warn.
	lastChange atomic.Int64
	sub        chan struct{}
	watch      *fsnotify.Watcher
	stop       chan struct{}
	done       chan struct{}
	lastCount  int // loaded-PSK count last logged on change (observability)
}

// defaultHealthInterval is how often the run loop's self-heal ticker
// fires when no config override is given. Chosen to be frequent enough
// that a transient dir-disappearance recovers within a handful of
// seconds, but slow enough that the periodic ReadDir is negligible.
const defaultHealthInterval = 15 * time.Second

// rescanFailEscalateAt is the number of consecutive rescan failures
// after which the per-failure log escalates from Warn to Error. The
// first few failures (e.g. a brief atomic-replace race on the dir) stay
// at Warn; sustained failure means the dir is genuinely gone and the
// operator needs a louder signal. The metric increments on every
// failure regardless of log level.
const rescanFailEscalateAt = 3

// fileEntry is a per-peer record loaded from the watched directory.
// psk is the 32 bytes from "<stem>.psk"; rpHash is the lowercase hex
// SHA-256 from the optional binding-hint companion (see
// bindingHintExt), or empty when no valid companion was found.
type fileEntry struct {
	psk    []byte
	rpHash string
	// prevPSK/prevRPHash hold the previous epoch's material for this
	// peer, carried in memory across rescans (window of 2). Populated
	// when a rescan observes the peer's PSK bytes change; dropped when
	// the peer's file disappears (peer removal is not a rotation).
	// Never persisted — restart loses the previous epoch by design.
	prevPSK    []byte
	prevRPHash string
}

// bindingHintExt is the on-disk filename extension for the optional
// binding-hint companion file ("<sha256-hex>.rpinfo"). The literal
// ".rpinfo" is an external-interface filename: it is an established
// contract with provisioning tooling / sidecars that drop these files
// into the PSK directory, so the on-disk name must not change even as
// the in-code vocabulary moves to "binding hint".
const bindingHintExt = ".rpinfo"

// bindingHintMaxBytes bounds how much we'll read from a binding-hint
// file. The valid payload is 64 hex chars; we allow a few extra bytes
// for trailing whitespace / newline. A file larger than this is
// treated as malformed and skipped without ever being slurped into
// memory.
const bindingHintMaxBytes = 80

// FileProviderConfig is exposed for tests; production callers use
// NewFileProvider with sensible defaults.
type FileProviderConfig struct {
	Dir      string
	Debounce time.Duration // default 250ms
	Logger   *slog.Logger  // default discard
	// Health overrides the self-heal ticker interval (watch-retry +
	// fallback rescan). Exposed for tests that need fast recovery;
	// production callers leave it zero to get defaultHealthInterval.
	Health time.Duration
	// StaleWarnAfter, when non-zero, enables a Warn log once the
	// snapshot has gone this long without a content change while
	// holding at least one PSK. Wire it to roughly 3-5x the sidecar's
	// rekey interval. Zero (default) disables the warning so static
	// never-rotating PSK directories stay quiet.
	StaleWarnAfter time.Duration
}

// NewFileProvider opens dir, performs an initial scan, and starts a
// background goroutine that watches for changes. The returned Provider
// is ready for Lookup immediately. Caller is responsible for Close.
func NewFileProvider(dir string, l *slog.Logger) (*FileProvider, error) {
	return NewFileProviderWithConfig(FileProviderConfig{Dir: dir, Logger: l})
}

// NewFileProviderWithConfig is the explicit-config variant of
// NewFileProvider; see FileProviderConfig for the available knobs.
func NewFileProviderWithConfig(cfg FileProviderConfig) (*FileProvider, error) {
	if cfg.Dir == "" {
		return nil, errors.New("pq: file provider requires a directory")
	}
	if cfg.Debounce == 0 {
		cfg.Debounce = 250 * time.Millisecond
	}
	if cfg.Health == 0 {
		cfg.Health = defaultHealthInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}

	// Absolutize so the dir-removed comparison in run() (which matches
	// fsnotify event paths, always absolute on linux, against p.dir)
	// works when the operator configured a relative path.
	if abs, err := filepath.Abs(cfg.Dir); err == nil {
		cfg.Dir = abs
	}

	if st, err := os.Stat(cfg.Dir); err != nil {
		return nil, fmt.Errorf("pq: stat %q: %w", cfg.Dir, err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("pq: %q is not a directory", cfg.Dir)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("pq: fsnotify: %w", err)
	}
	if err := w.Add(cfg.Dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("pq: watch %q: %w", cfg.Dir, err)
	}

	p := &FileProvider{
		dir:            cfg.Dir,
		debounce:       cfg.Debounce,
		health:         cfg.Health,
		staleWarnAfter: cfg.StaleWarnAfter,
		l:              cfg.Logger,
		sub:            make(chan struct{}, 1),
		watch:          w,
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}

	if err := p.rescan(); err != nil {
		_ = w.Close()
		return nil, err
	}
	if m := p.entries.Load(); m != nil {
		p.lastCount = len(*m)
	}
	cfg.Logger.Info("pq: file provider initialized", "dir", cfg.Dir, "psks", p.lastCount)
	go p.run()
	return p, nil
}

// Lookup returns the PSK for the given peer's static public key, or nil.
//
// Returns a freshly-allocated copy so callers can't accidentally
// mutate the live map storage. The internal map is replaced via
// atomic.Pointer on every rescan, so the slice we return wouldn't
// race with mutation in practice — but the cost of a 32-byte copy
// is negligible against handshake overhead, and the strict
// immutability contract keeps Provider implementations
// interchangeable without surprising lifetime aliasing.
func (p *FileProvider) Lookup(peerStaticPubKey []byte) []byte {
	if len(peerStaticPubKey) == 0 {
		return nil
	}
	m := p.entries.Load()
	if m == nil {
		return nil
	}
	sum := sha256.Sum256(peerStaticPubKey)
	e, ok := (*m)[hex.EncodeToString(sum[:])]
	if !ok || e.psk == nil {
		return nil
	}
	out := make([]byte, len(e.psk))
	copy(out, e.psk)
	return out
}

// LookupRPHash returns the lowercase hex SHA-256 of the provider
// pubkey expected to have derived the PSK for this peer, as recorded
// in the optional binding-hint companion file (see bindingHintExt).
// Returns "" when no companion file was loaded for the peer (absent,
// malformed, or unreadable) — callers treat that as "no binding info".
func (p *FileProvider) LookupRPHash(peerStaticPubKey []byte) string {
	if len(peerStaticPubKey) == 0 {
		return ""
	}
	m := p.entries.Load()
	if m == nil {
		return ""
	}
	sum := sha256.Sum256(peerStaticPubKey)
	return (*m)[hex.EncodeToString(sum[:])].rpHash
}

// LookupWithBinding returns the PSK and its companion binding hint
// (rpHash) from the same fileEntry in a single map load, so the two can
// never be read from inconsistent snapshots. ok is true iff a PSK was
// found; rpHash is "" when no valid .rpinfo companion was loaded for
// the peer. Returns a fresh copy of the PSK for the same caller-owned
// lifetime guarantees as Lookup.
func (p *FileProvider) LookupWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	if len(peerStaticPubKey) == 0 {
		return nil, "", false
	}
	m := p.entries.Load()
	if m == nil {
		return nil, "", false
	}
	sum := sha256.Sum256(peerStaticPubKey)
	e, found := (*m)[hex.EncodeToString(sum[:])]
	if !found || e.psk == nil {
		return nil, "", false
	}
	out := make([]byte, len(e.psk))
	copy(out, e.psk)
	return out, e.rpHash, true
}

// LookupPreviousWithBinding returns the previous-epoch PSK for the
// peer together with the binding hint recorded for THAT epoch, or
// ok=false when no rotation has been observed for the peer since
// startup. The previous epoch exists only in memory: it is populated
// when a rescan sees the peer's PSK change and is lost on restart.
func (p *FileProvider) LookupPreviousWithBinding(peerStaticPubKey []byte) (psk []byte, rpHash string, ok bool) {
	if len(peerStaticPubKey) == 0 {
		return nil, "", false
	}
	m := p.entries.Load()
	if m == nil {
		return nil, "", false
	}
	sum := sha256.Sum256(peerStaticPubKey)
	e, found := (*m)[hex.EncodeToString(sum[:])]
	if !found || e.prevPSK == nil {
		return nil, "", false
	}
	out := make([]byte, len(e.prevPSK))
	copy(out, e.prevPSK)
	return out, e.prevRPHash, true
}

func (p *FileProvider) Subscribe() <-chan struct{} {
	return p.sub
}

// Rescan forces a synchronous rescan. Exported for tests in other
// packages that need deterministic snapshot updates without waiting
// for fsnotify debounce.
func (p *FileProvider) Rescan() error { return p.rescan() }

// hasAnyPSK reports whether the last successful rescan loaded at
// least one PSK file. Used by HasPSK.
func (p *FileProvider) hasAnyPSK() bool {
	m := p.entries.Load()
	if m == nil {
		return false
	}
	return len(*m) > 0
}

// Status implements StatusReporter for the pq-status ssh command.
func (p *FileProvider) Status() ProviderStatus {
	st := ProviderStatus{Kind: "file", SnapshotAge: p.snapshotAge(time.Now()).Seconds()}
	m := p.entries.Load()
	if m == nil {
		return st
	}
	for stem, e := range *m {
		st.Peers = append(st.Peers, PeerPSKStatus{
			PeerKeyHash: stem,
			HasPSK:      e.psk != nil,
			HasPrev:     e.prevPSK != nil,
			RPHash:      e.rpHash,
		})
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].PeerKeyHash < st.Peers[j].PeerKeyHash })
	return st
}

func (p *FileProvider) Close() error {
	select {
	case <-p.stop:
		// already closing
	default:
		close(p.stop)
	}
	<-p.done
	return p.watch.Close()
}

// rescan reads every "<hex>.psk" file under dir, validates each is
// exactly 32 bytes with a 64-char lowercase hex stem, and atomically
// swaps the lookup map. Files that fail validation are logged and
// skipped (rather than failing the whole reload), so a single bad
// drop-in doesn't take the whole mesh offline.
//
// For each loaded PSK, also attempts to read the optional binding-hint
// companion file (see bindingHintExt). A valid companion is 64
// lowercase hex chars (plus optional trailing whitespace/newline)
// representing the SHA-256 of the peer's provider pubkey. Malformed,
// oversize, non-regular, or unreadable companion files are logged and
// the rpHash stays empty — the PSK still loads.
func (p *FileProvider) rescan() error {
	dirEntries, err := os.ReadDir(p.dir)
	if err != nil {
		return fmt.Errorf("pq: rescan %q: %w", p.dir, err)
	}
	next := make(map[string]fileEntry, len(dirEntries))
	for _, ent := range dirEntries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".psk") {
			continue
		}
		fullPath := filepath.Join(p.dir, name)
		// Open with O_NOFOLLOW (unix) or the closest equivalent
		// (windows) so a symlink that races our readdir cannot
		// redirect us to an arbitrary 32-byte file. This closes
		// the TOCTOU window an earlier Lstat()->ReadFile() pair
		// left open: an attacker who can write into the PSK
		// directory could swap a regular file for a symlink
		// between the two syscalls, turning a foreign file's
		// contents (eg leaked key material, kernel state) into a
		// peer's PSK. d_type-independent by construction, so this
		// is also correct on NFSv3 / FUSE filesystems where
		// readdir doesn't report a file type.
		fd, err := openPSKFileNoFollow(fullPath)
		if err != nil {
			p.l.Warn("pq: skipping psk file (open/nofollow failed)", "name", name, "err", err)
			continue
		}
		fi, err := fd.Stat()
		if err != nil {
			_ = fd.Close()
			p.l.Warn("pq: skipping psk file (stat failed)", "name", name, "err", err)
			continue
		}
		if !fi.Mode().IsRegular() {
			_ = fd.Close()
			p.l.Warn("pq: skipping non-regular psk file", "name", name, "mode", fi.Mode())
			continue
		}
		stem := strings.TrimSuffix(name, ".psk")
		if len(stem) != 64 {
			_ = fd.Close()
			p.l.Warn("pq: skipping psk file with non-sha256 name", "name", name)
			continue
		}
		stem = strings.ToLower(stem)
		// Filter non-hex stems to avoid map keys that can never match.
		if _, err := hex.DecodeString(stem); err != nil {
			_ = fd.Close()
			p.l.Warn("pq: skipping psk file with non-hex name", "name", name)
			continue
		}
		// Accept either raw 32 bytes (nebula-native format) OR
		// base64 of 32 bytes (44 chars, ~46 with trailing newline).
		// the provider's standard `key_out` writes base64 because its
		// primary downstream is WireGuard's PSK slot (which is
		// base64). Auto-detect by size + decode attempt; reject
		// anything else.
		const rawPSKLen = 32
		const b64MinLen = 44
		const b64MaxLen = 46 // 44 + optional "\r\n"
		if fi.Size() != rawPSKLen && (fi.Size() < b64MinLen || fi.Size() > b64MaxLen) {
			_ = fd.Close()
			p.l.Warn("pq: skipping psk file with wrong size", "name", name, "size", fi.Size())
			continue
		}
		buf := make([]byte, fi.Size())
		if _, err := io.ReadFull(fd, buf); err != nil {
			_ = fd.Close()
			p.l.Warn("pq: skipping psk file (read failed)", "name", name, "err", err)
			continue
		}
		_ = fd.Close()
		var raw []byte
		if len(buf) == rawPSKLen {
			raw = buf
		} else {
			trimmed := strings.TrimRight(string(buf), "\r\n")
			decoded, derr := base64.StdEncoding.DecodeString(trimmed)
			if derr != nil || len(decoded) != rawPSKLen {
				p.l.Warn("pq: skipping psk file (not raw 32B and not valid base64-of-32B)",
					"name", name, "size", fi.Size(), "err", derr)
				continue
			}
			raw = decoded
		}

		// Companion binding hint: best-effort, never blocks the PSK.
		rpHash := p.readBindingHint(stem)
		next[stem] = fileEntry{psk: raw, rpHash: rpHash}
	}

	// Carry previous-epoch material forward. For each peer present in
	// both snapshots: a changed PSK demotes the old current to
	// previous; an unchanged PSK keeps whatever previous we already
	// had. Peers absent from next drop both epochs implicitly.
	prevSnap := p.entries.Load()
	if prevSnap != nil {
		for k, ne := range next {
			oe, ok := (*prevSnap)[k]
			if !ok {
				continue
			}
			if !bytes.Equal(oe.psk, ne.psk) {
				ne.prevPSK = oe.psk
				ne.prevRPHash = oe.rpHash
			} else {
				ne.prevPSK = oe.prevPSK
				ne.prevRPHash = oe.prevRPHash
			}
			next[k] = ne
		}
	}

	if prevSnap == nil || !snapshotsEqual(*prevSnap, next) {
		p.lastChange.Store(time.Now().UnixNano())
	}
	p.entries.Store(&next)
	return nil
}

// snapshotsEqual reports whether two rescan snapshots carry identical
// content (same peers, same PSK bytes, same binding hints). Used to
// keep lastChange honest: health-tick rescans of an unchanged directory
// must not look like rotations.
func snapshotsEqual(a, b map[string]fileEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, ea := range a {
		eb, ok := b[k]
		if !ok || ea.rpHash != eb.rpHash || !bytes.Equal(ea.psk, eb.psk) {
			return false
		}
	}
	return true
}

// snapshotAge returns how long ago the snapshot content last changed.
func (p *FileProvider) snapshotAge(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, p.lastChange.Load()))
}

// checkStale drives the snapshot-age gauge and the optional
// staleness warning from the health ticker. *warned tracks the
// once-per-episode edge: Warn fires when age first crosses
// staleWarnAfter, and an Info marks recovery when fresh material
// arrives. The warning only fires while the snapshot holds at least
// one PSK — an empty directory is a provisioning state, not a dead
// rotator — and only when staleWarnAfter is configured.
func (p *FileProvider) checkStale(now time.Time, warned *bool) {
	age := p.snapshotAge(now)
	updateGauge(MetricFileSnapshotAge, age.Seconds())
	if p.staleWarnAfter <= 0 || !p.hasAnyPSK() {
		return
	}
	if age >= p.staleWarnAfter {
		if !*warned {
			*warned = true
			incCounter(MetricFileSnapshotStale)
			p.l.Warn("pq: psk directory content has not changed past the staleness threshold; if a rotating sidecar feeds this directory it may be dead or unable to reach its peers",
				"dir", p.dir, "age", age.Round(time.Second), "threshold", p.staleWarnAfter)
		}
		return
	}
	if *warned {
		*warned = false
		p.l.Info("pq: psk directory rotation resumed", "dir", p.dir)
	}
}

// readBindingHint loads the optional binding-hint companion file (see
// bindingHintExt) for the given PSK stem and returns the validated
// lowercase-hex SHA-256 inside it, or "" if the file is absent,
// unreadable, or malformed.
//
// Validation is strict: file must exist as a regular file (no symlink
// following), be at most bindingHintMaxBytes in size, and contain
// exactly 64 lowercase hex characters after trimming trailing
// whitespace. Anything else is a Warn-level skip — the PSK still loads
// with an empty rpHash, and callers treat "" as "no binding info".
func (p *FileProvider) readBindingHint(stem string) string {
	name := stem + bindingHintExt
	full := filepath.Join(p.dir, name)
	fd, err := openPSKFileNoFollow(full)
	if err != nil {
		if !os.IsNotExist(err) {
			p.l.Warn("pq: skipping binding hint (open/nofollow failed)", "name", name, "err", err)
		}
		return ""
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		p.l.Warn("pq: skipping binding hint (stat failed)", "name", name, "err", err)
		return ""
	}
	if !fi.Mode().IsRegular() {
		p.l.Warn("pq: skipping non-regular binding hint", "name", name, "mode", fi.Mode())
		return ""
	}
	if fi.Size() > bindingHintMaxBytes {
		p.l.Warn("pq: skipping oversize binding hint", "name", name, "size", fi.Size())
		return ""
	}
	// Decouple the read buffer size from fi.Size(): a writer that grows
	// the file between stat and read would otherwise leave us reading
	// only the stat-time prefix and silently truncating valid content.
	// Allocate the bound once and let io.ReadFull's short-read semantics
	// surface the actual length. The fi.Size() > bindingHintMaxBytes
	// check above still rejects obvious garbage at stat time without
	// ever slurping it into memory.
	buf := make([]byte, bindingHintMaxBytes)
	n, err := io.ReadFull(fd, buf)
	// io.ReadFull returns ErrUnexpectedEOF for a short read (n < len(buf))
	// and io.EOF only when n == 0. Both are expected here — the file is
	// almost certainly smaller than bindingHintMaxBytes — and only n
	// matters.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		p.l.Warn("pq: skipping binding hint (read failed)", "name", name, "err", err)
		return ""
	}
	got := strings.TrimRight(string(buf[:n]), " \t\r\n")
	if len(got) != 64 {
		p.l.Warn("pq: skipping binding hint with wrong length", "name", name, "len", len(got))
		return ""
	}
	// Reject mixed-case and non-hex up front so the stored value is
	// directly comparable to other lowercase-hex sums (cert
	// extension, sha256 of pubkey) without further normalisation.
	for i := 0; i < len(got); i++ {
		c := got[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			p.l.Warn("pq: skipping binding hint with non-lowercase-hex content", "name", name)
			return ""
		}
	}
	return got
}

// run is the background loop watching the directory. It coalesces
// fsnotify events with a quiet-window debounce, then rescans + notifies
// any subscriber.
//
// It additionally owns the provider's self-healing behaviour. Per the
// opportunistic-encryption principle, the last-known PSK snapshot is
// NEVER cleared just because the watched directory disappeared — those
// PSKs are still-valid key material and clearing them would break
// working tunnels. Instead:
//
//   - A Remove/Rename of the watched directory itself marks the watch
//     lost, fires an escalating log + watch_lost metric, and the
//     self-heal ticker keeps retrying watch.Add until the dir reappears.
//   - A failed rescan keeps the existing snapshot, counts toward an
//     escalating-Error threshold, and bumps the rescan_failed metric.
//   - A periodic health ticker re-adds the watch (when lost) and does a
//     fallback rescan, so the provider recovers even if the fsnotify
//     watch produced no event for the dir's reappearance.
func (p *FileProvider) run() {
	defer close(p.done)
	var pending bool
	var timer *time.Timer
	timerC := make(<-chan time.Time)

	// watchLost is set when the fsnotify watch on p.dir is no longer
	// active (dir removed/renamed). While set, the health ticker keeps
	// trying to re-establish it. rescanFails counts consecutive rescan
	// failures for the Warn→Error escalation. staleWarned tracks the
	// once-per-episode staleness warning edge (see checkStale).
	var watchLost bool
	var rescanFails int
	var staleWarned bool

	health := time.NewTicker(p.health)
	defer health.Stop()

	for {
		select {
		case <-p.stop:
			return

		case ev, ok := <-p.watch.Events:
			if !ok {
				return
			}
			// Only events that could affect the lookup table matter.
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			// The watched directory itself being removed/renamed means
			// our fsnotify registration is gone: no further events will
			// arrive until we re-Add it. Flag it loudly and let the
			// health ticker self-heal. Do NOT clear the snapshot.
			if (ev.Op&(fsnotify.Remove|fsnotify.Rename)) != 0 && filepath.Clean(ev.Name) == filepath.Clean(p.dir) {
				if !watchLost {
					watchLost = true
					incCounter(MetricFileWatchLost)
					p.l.Error("pq: psk directory watch lost (dir removed/renamed); serving last-known PSK snapshot, retrying watch",
						"dir", p.dir, "op", ev.Op.String())
				}
				// Still fall through to schedule a debounced rescan in
				// case the dir was atomically replaced.
			}
			pending = true
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(p.debounce)
			timerC = timer.C

		case err, ok := <-p.watch.Errors:
			if !ok {
				return
			}
			p.l.Warn("pq: fsnotify error", "err", err)

		case <-timerC:
			timerC = make(<-chan time.Time)
			if !pending {
				continue
			}
			pending = false
			p.attemptRescan(&rescanFails)

		case <-health.C:
			// Self-heal: re-establish a lost watch and do a fallback
			// rescan so a reappeared dir is picked up even if no event
			// fired. When the watch is healthy this is a cheap periodic
			// ReadDir that also catches any rescan we missed.
			if watchLost {
				if err := p.watch.Add(p.dir); err != nil {
					p.l.Error("pq: psk directory watch still unavailable; serving last-known PSK snapshot",
						"dir", p.dir, "err", err)
				} else {
					watchLost = false
					p.l.Warn("pq: psk directory watch re-established; resyncing snapshot", "dir", p.dir)
				}
			}
			p.attemptRescan(&rescanFails)
			p.checkStale(time.Now(), &staleWarned)
		}
	}
}

// attemptRescan runs a single rescan, retaining the existing snapshot
// on failure (stale PSKs are valid material) while tracking consecutive
// failures for Warn→Error escalation and incrementing the
// rescan_failed metric on every failure. On success it resets the
// failure counter and notifies any subscriber. *fails is the loop's
// running consecutive-failure count.
func (p *FileProvider) attemptRescan(fails *int) {
	if err := p.rescan(); err != nil {
		*fails++
		incCounter(MetricFileRescanFailed)
		if *fails >= rescanFailEscalateAt {
			p.l.Error("pq: psk directory rescan failing repeatedly; serving last-known PSK snapshot",
				"dir", p.dir, "consecutiveFailures", *fails, "err", err)
		} else {
			p.l.Warn("pq: rescan failed; retaining last-known PSK snapshot", "dir", p.dir, "err", err)
		}
		return
	}
	if *fails > 0 {
		p.l.Warn("pq: psk directory rescan recovered", "dir", p.dir, "afterFailures", *fails)
		*fails = 0
	}
	n := 0
	if m := p.entries.Load(); m != nil {
		n = len(*m)
	}
	if n != p.lastCount {
		p.l.Info("pq: psk snapshot changed", "dir", p.dir, "psks", n, "was", p.lastCount)
		p.lastCount = n
	}
	// Coalesce subscriber notifications: send if buffer empty,
	// otherwise the existing pending event covers this round.
	select {
	case p.sub <- struct{}{}:
	default:
	}
}

// discard is a tiny io.Writer that drops everything; used as the
// default logger sink so we don't spam stderr in tests.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
