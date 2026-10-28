package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/DefinedNet/dnsconfig"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

// This file turns the `dns` stanza into a host DNS configuration and applies it
// to the host OS through a dnsconfig.Manager. It is in two parts: the stanza
// and its parsers, and the hostDNS that owns the Manager and ties it to
// nebula's config reloads and Control lifecycle.

const defaultHostDNSIdentity = "nebula"

// hostDNSConfig is the `dns` stanza, loaded.
type hostDNSConfig struct {
	// hostDNSOptions is what we need to build the Manager, while hostDNSGoal
	// is what we want the host's DNS resolution to look like.
	hostDNSOptions
	hostDNSGoal
}

// hostDNSOptions configures the Manager. They are fixed for its life.
type hostDNSOptions struct {
	// Identity scopes this instance's DNS artifacts, cleanup, and the
	// cross-process lock inside dnsconfig. It must be stable across restarts
	// and distinct for dnsconfig Manager on the host.
	Identity string

	// Interface is the tun device's name, which Windows needs to write DNS
	// settings. It is tun.dev, which is fixed for the life of the process,
	// that means a Manager can be built with it before the device exists.
	Interface string
}

// What we want to do to the host's resolver.
type hostDNSGoal struct {
	enabled bool
	dns     dnsconfig.Config
}

// loadHostDNSConfig reads and validates the `dns` stanza. It does not ask
// whether this host can honour it. A disabled stanza ignores the resolver
// keys.
//
// On error the goal is set like a disabled stanza, but the options are
// still returned when they loaded. That lets a caller clear stale host
// data even though the rest of the stanza is unusable.
//
// tunDisabled is whether this process runs without a tun device.
func loadHostDNSConfig(c *config.C, tunDisabled bool) (hostDNSConfig, error) {
	var cfg hostDNSConfig
	var optsErr, goalErr error
	cfg.hostDNSOptions, optsErr = loadIdentityConfig(c)
	cfg.hostDNSGoal, goalErr = loadHostDNSGoal(c, tunDisabled)
	if err := joinDNSErrors(optsErr, goalErr); err != nil {
		cfg.hostDNSGoal = hostDNSGoal{}
		return cfg, err
	}
	return cfg, nil
}

// loadIdentityConfig reads dns.identity and tun.dev.
func loadIdentityConfig(c *config.C) (hostDNSOptions, error) {
	identity, err := parseDNSIdentity(c)
	if err != nil {
		return hostDNSOptions{}, err
	}
	return hostDNSOptions{Identity: identity, Interface: c.GetString("tun.dev", "")}, nil
}

// loadHostDNSGoal reads dns.enabled and, when it is on, the desired resolver
// configuration. It keeps checking after a key fails, so one bad stanza can
// report several problems at once.
func loadHostDNSGoal(c *config.C, tunDisabled bool) (hostDNSGoal, error) {
	g := hostDNSGoal{enabled: c.GetBool("dns.enabled", false)}
	if !g.enabled {
		return g, nil
	}

	var tunErr, nameserversErr, domainsErr error
	if tunDisabled {
		tunErr = errors.New("dns.enabled requires a tun device, but tun.disabled is true")
	}
	g.dns.Nameservers, nameserversErr = parseDNSNameservers(c)
	g.dns.SearchDomains, g.dns.MatchDomains, domainsErr = parseDNSDomainLists(c)
	if err := joinDNSErrors(tunErr, nameserversErr, domainsErr); err != nil {
		return hostDNSGoal{}, err
	}

	if err := g.dns.Validate(); err != nil {
		return hostDNSGoal{}, util.NewContextualError("dns is not a valid DNS configuration", nil, err)
	}
	return g, nil
}

// joinDNSErrors reports a batch of validation failures as one error.
//
// A lone error is handed back unwrapped rather than joined, and no errors at
// all is nil.
func joinDNSErrors(errs ...error) error {
	errs = slices.DeleteFunc(slices.Clone(errs), func(err error) bool { return err == nil })
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	return errors.Join(errs...)
}

func parseDNSNameservers(c *config.C) ([]netip.Addr, error) {
	raw, err := c.GetStringSliceStrict("dns.nameservers")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("dns.nameservers must have at least one entry")
	}

	var errs []error
	out := make([]netip.Addr, 0, len(raw))
	for i, rawAddr := range raw {
		addr, err := netip.ParseAddr(rawAddr)
		if err != nil {
			errs = append(errs, util.NewContextualError(
				fmt.Sprintf("entry %v in dns.nameservers is not an IP address", i+1),
				m{"addr": rawAddr},
				err,
			))
			continue
		}
		out = append(out, addr)
	}

	if len(errs) > 0 {
		return nil, joinDNSErrors(errs...)
	}

	return out, nil
}

// parseDNSDomains reads a list of domain suffixes at key k. Entries are handed
// to dnsconfig as written: it compares and publishes them case-insensitively
// and with or without the trailing dot.
func parseDNSDomains(c *config.C, k string) ([]string, error) {
	// Strict because no match domains is the explicit opt in to catch-all DNS:
	// GetStringSlice would read "match_domains: mesh.example.com", a one entry
	// list missing its dash, as no match domains at all and silently point
	// every query on the host at dns.nameservers.
	raw, err := c.GetStringSliceStrict(k)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var errs []error
	for i, domain := range raw {
		switch domain {
		case "":
			errs = append(errs, fmt.Errorf("entry %v in %s is empty", i+1, k))
		case ".":
			// Don't allow '.'. If the user wants to take over everything, they should
			// explicitly configure no match_domains.
			errs = append(errs, fmt.Errorf(`entry %v in %s is the root domain; set "match_domains: []" to send every query to dns.nameservers`, i+1, k))
		}
	}

	if len(errs) > 0 {
		return nil, joinDNSErrors(errs...)
	}

	return raw, nil
}

// parseDNSDomainLists reads dns.search_domains and dns.match_domains. We read
// them together so we can properly handle the fallback behavior when search_domains
// is specified but match_domains is not.
func parseDNSDomainLists(c *config.C) (search, match []string, err error) {
	var errs []error

	search, err = parseDNSDomains(c, "dns.search_domains")
	if err != nil {
		errs = append(errs, err)
	}

	switch {
	case c.IsSet("dns.match_domains"):
		match, err = parseDNSDomains(c, "dns.match_domains")
		if err != nil {
			errs = append(errs, err)
		}

	case len(errs) > 0:
		// search_domains is what needs fixing; say nothing else about it.

	case len(search) == 0:
		errs = append(errs, errors.New(`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`))

	default:
		match = slices.Clone(search)
	}

	return search, match, joinDNSErrors(errs...)
}

// parseDNSIdentity loads the identity we use for tracking our changes to the local
// resolver configuration. This value is used to disambiguate changes from other
// users of the dnsconfig library, and to recover original OS state in the event
// of an unclean shutdown.
func parseDNSIdentity(c *config.C) (string, error) {
	identity := c.GetString("dns.identity", defaultHostDNSIdentity)
	if err := dnsconfig.ValidateIdentity(identity); err != nil {
		return "", fmt.Errorf("dns.identity is not usable: %w", err)
	}
	return identity, nil
}

// hostDNSState tracks the hostDNS lifecycle.
type hostDNSState int

const (
	hostDNSNew hostDNSState = iota
	hostDNSStarted
	hostDNSStopped
)

// hostDNS turns the `dns` stanza into goals for a dnsconfig.Manager.
//
// We maintain a single Manager for the lifetime of nebula.
type hostDNS struct {
	l *slog.Logger
	// newManager is for testing; nil means newDNSConfigManager.
	newManager func(dnsconfig.Options) (*dnsconfig.Manager, error)
	// warnedUnsupported is whether an enabled stanza has been told this host
	// can't be configured. It primarily exists for testing, but also serves
	// to avoid logging multiple times in the case where it's never going to
	// work.
	warnedUnsupported bool
	// tunDisabled is whether this process runs without a tun device. It is
	// read once at construction: tun.disabled only takes effect on restart,
	// so we don't need to track it through reloads.
	tunDisabled bool

	// mu serializes Recover, Start, Restore, and the reload callback. It is
	// held across restore to prevent a reload from landing, and meddling with
	// Restore's work.
	mu     sync.Mutex
	runCfg hostDNSConfig
	// state is used to track where we sit relative to the Manager. Start
	// moves it to started, Restore moves it to stopped. A reload when in New
	// or Stopped only loads config, but doesn't try to do anything.
	state hostDNSState

	// mgr is built lazily, when we first need it. mgrOpts is what it was built
	// from, so we can log things appropriately.
	mgr     *dnsconfig.Manager
	mgrOpts hostDNSOptions
}

// newHostDNSFromConfig builds a hostDNS and registers a reload callback.
//
// A stanza that does not load is returned as an error, and the caller is
// expected to treat it as fatal. Recover and Restore can still clear stale
// host dns configuration from a prior unclean shutdown, as long as we managed
// to load our identity.
func newHostDNSFromConfig(l *slog.Logger, c *config.C) (*hostDNS, error) {
	s := &hostDNS{
		l:           l.With("subsystem", "host_dns"),
		tunDisabled: c.GetBool("tun.disabled", false),
	}

	cfg, err := loadHostDNSConfig(c, s.tunDisabled)
	s.runCfg = cfg
	if err != nil {
		if cfg.Identity == "" {
			return nil, err
		}
		return s, err
	}

	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		r.RestartRequiredIfChanged("dns.identity")
		if err := s.reload(c); err != nil {
			s.l.Error("Failed to reload host DNS from config", "error", err)
			r.Failed()
		}
	})
	return s, nil
}

// reload loads the configuration a HUP delivered and states its goal.
func (s *hostDNS) reload(c *config.C) error {
	cfg, err := loadHostDNSConfig(c, s.tunDisabled)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.runCfg = cfg
	return s.convergeLocked()
}

// Recover makes removing whatever a previous run left behind the goal, so a
// crash never leaves the host pointed at a nameserver that is no longer
// reachable. Main calls it once, before anything that could fail and leave
// such a crash unrepaired, and whether or not the stanza is enabled. It does
// not wait for the removal: Start's goal supersedes it, and Restore completes
// it if Start never comes.
func (s *hostDNS) Recover() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != hostDNSNew || s.mgr != nil {
		return
	}
	if err := s.deactivateLocked(); err != nil {
		s.l.Error("Failed to start host DNS recovery", "error", err)
	}
}

// Start latches that the tun device is active and registers the goal. Control
// calls it once, after activating the device; this is what Control.hostDNSStart
// points at.
//
// The latch is the whole reason this is separate from converge: nebula arms
// SIGHUP before Control activates the device, so a reload landing in that
// window would otherwise apply against a link that is not up yet. A reload
// that early only loads its configuration, which is applied here.
func (s *hostDNS) Start() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == hostDNSNew {
		// Only move to started from new: a Restore that beat us here has
		// already declared the host off limits.
		s.state = hostDNSStarted
	}

	if err := s.convergeLocked(); err != nil {
		s.l.Error("Failed to apply host DNS config", "error", err)
	}
}

// convergeLocked registers the goal the configuration asks for and returns.
// Set and Clear only record the goal; dnsconfig applies it and repairs drift in
// the background, logging failures through our logger.
//
// Safe to call when host DNS is disabled, and when nothing was ever applied.
// It no-ops until Start has latched the tun device as active.
func (s *hostDNS) convergeLocked() error {
	if s.state != hostDNSStarted {
		return nil
	}
	if !s.runCfg.enabled {
		// Deactivate rather than Restore: this is reversible, so the Manager
		// stays live for the reload that turns host DNS back on. It is also
		// how a start with the stanza off recovers what a crash left behind.
		return s.deactivateLocked()
	}
	return s.applyLocked(s.runCfg.dns)
}

// applyLocked updates dnsconfig's goal if necessary.
func (s *hostDNS) applyLocked(desired dnsconfig.Config) error {
	if err := s.ensureManagerLocked(); err != nil {
		if errors.Is(err, errHostDNSUnsupported) {
			// Unrecoverable, and not a reason to keep the tunnel down: the
			// same stanza may be doing its job on the mesh's other hosts.
			if !s.warnedUnsupported {
				s.l.Warn("host DNS configuration is not supported on this host; leaving host DNS unmanaged", "reason", err)
				s.warnedUnsupported = true
			}
			return nil
		}
		return err
	}
	if st := s.mgr.Status(); st.Goal == dnsconfig.GoalSet && st.Desired.Equal(desired) {
		return nil
	}

	if err := s.mgr.Set(desired); err != nil {
		if errors.Is(err, dnsconfig.ErrInterfaceRequired) {
			return fmt.Errorf("%w: set tun.dev so the adapter can be named", err)
		}
		return err
	}
	if !desired.IsSplit() {
		s.l.Info("host DNS config has no match_domains; overriding all host DNS resolution")
	}
	s.l.Info("host DNS config requested",
		"identity", s.mgrOpts.Identity, "resolvers", desired.Nameservers,
		"matchDomains", desired.MatchDomains, "searchDomains", desired.SearchDomains)
	return nil
}

// deactivateLocked tells dnsconfig to remove our state, including anything
// left behind by a prior run.
func (s *hostDNS) deactivateLocked() error {
	if err := s.ensureManagerLocked(); err != nil {
		if errors.Is(err, errHostDNSUnsupported) {
			s.l.Debug("Skipping host DNS cleanup", "reason", err)
			return nil
		}
		return err
	}
	wasSet := s.mgr.Status().Goal == dnsconfig.GoalSet
	if err := s.mgr.Clear(); err != nil {
		return err
	}
	if wasSet {
		s.l.Info("host DNS config removal requested", "identity", s.mgrOpts.Identity)
	}
	return nil
}

// ensureManagerLocked builds the Manager if there is none. Note that the
// Manager won't do anything until we give it a goal.
func (s *hostDNS) ensureManagerLocked() error {
	if s.mgr != nil {
		return nil
	}

	newManager := s.newManager
	if newManager == nil {
		newManager = newDNSConfigManager
	}
	opts := s.runCfg.hostDNSOptions
	mgr, err := newManager(dnsconfig.Options{
		Identity:      opts.Identity,
		Logger:        s.l,
		InterfaceName: opts.Interface,
	})
	if err != nil {
		return err
	}
	s.mgr, s.mgrOpts = mgr, opts
	return nil
}

// errHostDNSUnsupported means dnsconfig would refuse every attempt on this
// host, so no Manager is built for it.
var errHostDNSUnsupported = errors.New("host DNS configuration is not supported on this host")

// hostDNSNewTimeout bounds manager construction, which initializes the backend.
const hostDNSNewTimeout = 5 * time.Second

// newDNSConfigManager builds a dnsconfig.Manager, or reports an error if
// we can't, except on Windows where we rely on dnsconfig itself reporting
// the error.
func newDNSConfigManager(o dnsconfig.Options) (*dnsconfig.Manager, error) {
	switch dnsconfig.Detect() {
	case dnsconfig.BackendNoop:
		return nil, fmt.Errorf("%w: no dnsconfig backend for %s", errHostDNSUnsupported, runtime.GOOS)
	case dnsconfig.BackendDarwin:
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("%w: requires root on macOS", errHostDNSUnsupported)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), hostDNSNewTimeout)
	defer cancel()
	return dnsconfig.New(ctx, o)
}

// Restore puts the host's previous DNS configuration back and releases the
// Manager. Call it before the tunnels and tun go away. It is idempotent and
// safe to call when nothing was ever applied, and on a nil hostDNS.
func (s *hostDNS) Restore() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = hostDNSStopped
	s.closeManagerLocked()
}

// closeManagerLocked closes the Manager, reverting whatever it applied. It is
// safe to call with no Manager.
func (s *hostDNS) closeManagerLocked() {
	if s.mgr == nil {
		return
	}
	mgr := s.mgr
	s.mgr = nil
	owed := owesCleanup(mgr.Status())
	err := mgr.Close()
	switch {
	case err != nil:
		s.l.Warn("failed to revert host DNS config; rerun with the same identity to try again",
			"identity", s.mgrOpts.Identity, "error", err)
	case errors.Is(mgr.Status().LastError, dnsconfig.ErrManagerAlreadyRunning):
		s.l.Warn("host DNS identity is held by another running process; not updating host DNS", "identity", s.mgrOpts.Identity)
	case owed:
		s.l.Info("restored the previous host DNS config", "identity", s.mgrOpts.Identity)
	}
}

// owesCleanup reports whether a manager in st may have host DNS config of
// ours to remove.
func owesCleanup(st dnsconfig.Status) bool {
	return st.Goal == dnsconfig.GoalSet || st.Goal == dnsconfig.GoalClear && !st.Converged
}
