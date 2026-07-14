package nebula

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/slackhq/nebula/config"
)

// nebulaSelfToken is a magic host value usable in the host position of a
// listener config (e.g. "<nebula>:8080"). It expands to every one of this
// host's overlay/VPN addresses, giving bind-ALL semantics across the VPN.
//
// "<" and ">" are illegal in hostnames, so the token is safe by construction:
// it must be intercepted and expanded before any resolver call, and if a call
// site ever forgets to expand it, name resolution fails loud rather than
// silently resolving to something unexpected.
const nebulaSelfToken = "<nebula>"

// resolveSelfListenAddrs expands the "<nebula>" self-token in a listener
// address into one host:port string per VPN address, or returns the original
// address unchanged when the token is absent.
//
// Callers pass the current set of VPN addresses at LISTENER-START time, read
// reload-safe from pki.getCertState().myVpnAddrs. Note that because expansion
// happens when a listener starts, a cert reload that changes myVpnAddrs does
// NOT by itself rebind an already-bound listener; the previously expanded
// addresses stay bound until that listener restarts (its config section
// changes, its feature toggles, or the process restarts).
func resolveSelfListenAddrs(listenAddr string, vpnAddrs []netip.Addr) ([]string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// If the token is present but the value isn't host:port form, the user
		// clearly meant to use it, so fail loud. Otherwise defer to the bind,
		// matching today's behavior for malformed values.
		if strings.Contains(listenAddr, nebulaSelfToken) {
			return nil, fmt.Errorf("%q must be used in host:port form, got %q", nebulaSelfToken, listenAddr)
		}
		return []string{listenAddr}, nil
	}

	if host != nebulaSelfToken {
		// The token as a substring of a larger host (e.g. "<nebula>.corp") is
		// almost certainly a typo. It can't resolve ("<"/">" are illegal in
		// hostnames) so it would fail loud at bind anyway, but erroring here
		// gives a clear message instead of an opaque resolver failure.
		if strings.Contains(host, nebulaSelfToken) {
			return nil, fmt.Errorf("%q must be the entire host to expand, got host %q in %q", nebulaSelfToken, host, listenAddr)
		}
		// Return the original string byte-for-byte so every existing config
		// behaves exactly as before, including the "[::]" special cases that
		// callers handle independently of this helper.
		return []string{listenAddr}, nil
	}

	if port == "" {
		// SplitHostPort accepts an empty port (binding an ephemeral port), but
		// for the token that is never intended, so require one explicitly.
		return nil, fmt.Errorf("%q requires an explicit port, got %q", nebulaSelfToken, listenAddr)
	}

	if len(vpnAddrs) == 0 {
		return nil, fmt.Errorf("cannot expand %q in listen address %q: host has no VPN addresses", nebulaSelfToken, listenAddr)
	}

	addrs := make([]string, len(vpnAddrs))
	for i, a := range vpnAddrs {
		// JoinHostPort brackets IPv6 automatically.
		addrs[i] = net.JoinHostPort(a.Unmap().String(), port)
	}
	return addrs, nil
}

// warnSelfTokenWithTunDisabled logs a warning for each listener whose config
// uses the "<nebula>" self-token while tun.disabled is set. The token expands
// to this host's overlay addresses, which no interface carries when the tun is
// disabled, so those listeners cannot bind. The common footgun is enabling DNS
// with "<nebula>" on a tun-disabled lighthouse.
func warnSelfTokenWithTunDisabled(l *slog.Logger, c *config.C) {
	if !c.GetBool("tun.disabled", false) {
		return
	}
	for _, key := range []string{"lighthouse.dns.host", "sshd.listen", "stats.listen"} {
		if strings.Contains(c.GetString(key, ""), nebulaSelfToken) {
			l.Warn(`Listener uses the "<nebula>" self-token but tun.disabled is set; overlay addresses are not bindable without a tun interface, so this listener will fail to bind`,
				"configKey", key)
		}
	}
}
