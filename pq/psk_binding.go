package pq

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/slackhq/nebula/cert"
)

// PqPskBindingMode controls how strictly nebula enforces the cert v2
// PqPskBinding extension against any per-PSK provider binding hint
// (today: the FileProvider's binding-hint companion file). The check
// fires at PSK-use time on both initiator and responder paths.
//
// The default (PqPskBindingWarn) is fully backwards compatible: it
// never refuses a PSK, only logs when a cert claim is present without a
// matching provider binding hint (or vice-versa). Operators graduating
// to a fleet where every cert has the extension can switch to
// PqPskBindingEnforce to fail closed on a sidecar that's been re-keyed
// since the cert was signed.
type PqPskBindingMode int

const (
	// PqPskBindingOff disables the check entirely. The PSK is used
	// without consulting either the cert extension or the provider
	// binding hint. Useful for operators who have no PQ-PSK provider
	// integration but want to silence the warn-mode logs.
	PqPskBindingOff PqPskBindingMode = iota
	// PqPskBindingWarn (default) logs mismatches but always uses the
	// PSK. Picked as default because it preserves pre-extension
	// behaviour for fleets that haven't yet re-issued certs with the
	// PqPskBinding extension.
	PqPskBindingWarn
	// PqPskBindingEnforce refuses the PSK when the peer's cert claims a
	// PQ-PSK binding (extension present) but the local provider binding
	// hint is missing or doesn't match. Logs at Error.
	//
	// Failure surfaces differently by path:
	//
	//   - Initiator: a refused PSK causes buildHandshakeState to return
	//     an error, the handshake never goes on the wire, and the
	//     operator sees an immediate failure they can act on (rotate the
	//     provider binding hint, re-sign cert, or drop back to
	//     PqPskBindingWarn).
	//
	//   - Responder: a refused PSK causes injectResponderPSK to fail,
	//     the Machine marks the in-flight packet as failed, and the
	//     packet is dropped. The initiator has no way to learn the
	//     responder refused the binding — its next attempt will use
	//     the same subtype and be dropped again. The result is a
	//     connectivity blackout for that peer pair until the binding
	//     mismatch is resolved or one side is dropped to warn mode.
	//
	// There is no automatic IXPSK0 fallback on either path: in enforce
	// mode the operator has declared they want to fail rather than
	// silently degrade. Use PqPskBindingWarn during rollouts where you
	// can't yet guarantee every peer's provider binding hint matches its
	// signed cert.
	PqPskBindingEnforce
)

// String returns the canonical config form of m.
func (m PqPskBindingMode) String() string {
	switch m {
	case PqPskBindingOff:
		return "off"
	case PqPskBindingWarn:
		return "warn"
	case PqPskBindingEnforce:
		return "enforce"
	default:
		return fmt.Sprintf("pq_psk_binding(%d)", int(m))
	}
}

// ParsePqPskBindingMode resolves a config string into a PqPskBindingMode.
// Empty / unset defaults to PqPskBindingWarn so existing operators see
// no behaviour change. Unknown values return an error rather than
// silently falling through; misconfiguration should be loud.
func ParsePqPskBindingMode(s string) (PqPskBindingMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "warn":
		return PqPskBindingWarn, nil
	case "off", "disabled":
		return PqPskBindingOff, nil
	case "enforce", "strict":
		return PqPskBindingEnforce, nil
	}
	return 0, fmt.Errorf("pq: unknown psk_binding mode %q (expected: off|warn|enforce)", s)
}

// BindingInputs carries every source of PQ-PSK binding evidence that
// ValidatePSKBindingInputs reasons over.
//
// All fields are lowercase hex (no leading 0x). Empty means "no claim
// from this source"; only non-empty sources participate in the
// match/mismatch decision tree.
type BindingInputs struct {
	// CertHash is the peer's CA-signed PqPskBinding cert extension (cert
	// v2). The strongest source: a mismatch with any other source under
	// PqPskBindingEnforce is a hard refuse, because the only ways to
	// forge this hash are (a) the operator's CA was compromised or (b)
	// someone re-keyed the sidecar after the cert was signed. Empty for
	// v1 certs and v2 certs without the extension.
	CertHash string

	// GossipedHash is the hash the peer advertised over lighthouse
	// HostUpdate. The peer claims this is its own current PQ-PSK
	// binding. Not CA-signed — a malicious peer could lie. Used as
	// supporting evidence: agreeing with CertHash strengthens trust;
	// under enforce mode a mismatch with CertHash is fatal.
	GossipedHash string

	// LocalProviderHash is the hash the operator stored on this node in
	// the provider binding hint next to the per-peer PSK. Operator-
	// controlled; sees no PKI signature. Mismatch with CertHash under
	// enforce mode is fatal (operator rotated the sidecar without
	// re-issuing the cert).
	LocalProviderHash string
}

// ValidatePSKBinding is the legacy two-source entry point preserved for
// backwards compatibility. It composes a BindingInputs with no gossip
// claim and forwards to ValidatePSKBindingInputs; prefer the latter for
// new call sites.
func ValidatePSKBinding(mode PqPskBindingMode, peerCert cert.Certificate, rpHash string, logger *slog.Logger) bool {
	in := BindingInputs{
		CertHash:          certHashHex(peerCert),
		LocalProviderHash: rpHash,
	}
	return validateBinding(mode, in, logger)
}

// ValidatePSKBindingInputs cross-checks every available source of PQ-PSK
// binding evidence. Returns true if the PSK should be used; false if
// mode is PqPskBindingEnforce and the binding fails.
//
// Decision priority:
//
//  1. If a CertHash is present (peer cert v2 extension), it is
//     authoritative. Enforcement decisions only consider CertHash vs
//     LocalProviderHash (operator-controlled, on this node).
//     GossipedHash is diagnostic-only when CertHash is present: a peer
//     that gossips a hash disagreeing with its own CA-signed cert is
//     lying about itself, and we log a Warn — but we do NOT refuse the
//     PSK on the basis of an unsigned peer self-report. Refusing on
//     gossip would let any compromised peer (or a compromised lighthouse
//     forwarding gossip) DoS its own PQ handshake, and worse, hand an
//     attacker a way to suppress PQ for selected peers by forging
//     gossip.
//
//  2. Without a CertHash, GossipedHash and LocalProviderHash are both
//     accepted as supporting evidence. If both are present and equal
//     the binding passes silently. If they disagree, warn-mode logs;
//     enforce mode still allows the PSK (no CA claim to enforce).
//
//  3. With only one of (GossipedHash, LocalProviderHash) and no
//     CertHash, the PSK is used silently — there is no second source
//     to contradict the single observation.
//
// Logging is informational on the warn paths and Error on the
// enforce-refused paths so operators see exactly why a PSK was
// dropped without having to enable debug logging. The logger is
// expected to already carry peer context (vpnAddr, fingerprint) via
// With(); ValidatePSKBindingInputs adds only the hash values that
// disambiguate the specific mismatch.
//
// Logger may be nil; the function elides logging in that case so test
// doubles don't need to inject one just to exercise the decision tree.
func ValidatePSKBindingInputs(mode PqPskBindingMode, in BindingInputs, logger *slog.Logger) bool {
	return validateBinding(mode, in, logger)
}

// certHashHex extracts the hex-encoded PQ-PSK binding from a peer cert,
// or "" if absent / malformed. Defence-in-depth: the cert package
// already rejects malformed extensions at parse time.
func certHashHex(peerCert cert.Certificate) string {
	if peerCert == nil {
		return ""
	}
	h := peerCert.PqPskBinding()
	if len(h) != cert.PqPskBindingLen {
		return ""
	}
	return hex.EncodeToString(h)
}

func validateBinding(mode PqPskBindingMode, in BindingInputs, logger *slog.Logger) bool {
	if mode == PqPskBindingOff {
		return true
	}

	ch := in.CertHash
	gh := in.GossipedHash
	rh := in.LocalProviderHash

	// Cert is authoritative. With a cert claim present, the operator-
	// controlled provider binding hint is the only source that can
	// refuse a PSK under enforce mode. Gossip is peer self-report
	// (unsigned) and is logged-but-never-enforced when it disagrees with
	// the cert.
	if ch != "" {
		// Peer's live gossip claim. A disagreement with the CA-signed
		// cert is the loudest mismatch — the peer is contradicting its
		// own CA — but the cert is the trust anchor, not the gossip.
		// Logging a Warn here surfaces the lying peer (or a compromised
		// gossip path) without giving that peer a lever to refuse its
		// own PSK setup. The PSK decision below is made against the
		// provider binding hint, not gossip.
		if gh != "" && gh != ch {
			if logger != nil {
				logger.Warn("pq: peer-gossiped PQ-PSK binding disagrees with CA-signed cert (ignoring gossip; cert is authoritative)",
					"certHash", ch, "gossipHash", gh)
			}
		}

		if rh != "" && rh != ch {
			// Machine-readable trace of the mismatch, independent of mode
			// (warn keeps the PSK, enforce drops it — the event is the same).
			incCounter(MetricBindingMismatch)
			if mode == PqPskBindingEnforce {
				if logger != nil {
					logger.Error("pq: refusing PSK; PQ-PSK binding mismatch",
						"certHash", ch, "providerHash", rh)
				}
				return false
			}
			if logger != nil {
				logger.Warn("pq: PQ-PSK binding mismatch (using PSK anyway under warn mode)",
					"certHash", ch, "providerHash", rh)
			}
			return true
		}

		if rh == "" {
			// Cert claims a binding but we have no operator-controlled
			// provider binding hint to confirm it against. Warn-mode
			// tolerates this; enforce refuses. Gossip is intentionally
			// excluded as a confirming source — it's peer self-report
			// (see header comment) — so a peer cannot save itself from an
			// enforce-mode refuse by gossiping any hash it likes.
			if mode == PqPskBindingEnforce {
				if logger != nil {
					logger.Error("pq: refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present",
						"expectedRPHash", ch)
				}
				return false
			}
			if logger != nil {
				logger.Warn("pq: peer cert claims PQ-PSK binding but no provider binding hint present",
					"expectedRPHash", ch)
			}
			return true
		}

		// ch is set, and the provider binding hint agrees. Gossip
		// mismatch (if any) was logged above without affecting the
		// decision.
		return true
	}

	// No CA-signed claim. Gossip and the provider binding hint can still
	// be informational signals but neither can refuse — there's nothing
	// to enforce.
	switch {
	case gh == "" && rh == "":
		// No claim, no info — silent. The common case for cert-v1
		// deployments or v2 deployments without the extension and no
		// provider binding hint sidecar.
		return true

	case gh != "" && rh != "" && gh != rh:
		// Two unsigned sources disagree. Log under warn mode; under
		// enforce we still allow — no CA claim is being contradicted.
		if logger != nil {
			logger.Warn("pq: gossip/provider PQ-PSK binding disagree (no CA claim to enforce)",
				"gossipHash", gh, "providerHash", rh)
		}
		return true

	case rh != "" && gh == "":
		// We have a local origin claim but the peer cert binds none.
		// Either the operator dropped a provider binding hint next to a
		// peer whose CA hasn't been upgraded, or the peer is on cert v1.
		// Use the PSK — there's nothing claimed to verify against — but
		// log so the operator can investigate.
		//
		// The provider hash is intentionally omitted from this log:
		// it's operator-controlled (not secret) but acts as a stable
		// per-peer fingerprint, and warn-mode rollouts would fire
		// this event for every unbound peer. The hash is still on
		// disk in the provider binding hint if needed; the surrounding
		// logger context already identifies the peer.
		// Warn (not Info): production deployments commonly run at Warn
		// level and "investigate this" signals must survive that filter.
		if logger != nil {
			logger.Warn("pq: provider binding hint present but peer cert has no PQ-PSK binding to verify against")
		}
		return true

	default:
		// Either gossip-only, or gossip+provider hint agree. Silent.
		return true
	}
}
