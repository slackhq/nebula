package handshake

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
)

// PSKLookupFunc returns the 32-byte PQ PSK to use with the peer identified
// by the given static public key, or nil if no PSK is configured for that
// peer. For mesh-wide PSK mode (subtype 0), the implementation may ignore
// peerStaticPubKey and return the same bytes for every call.
//
// peerCert is the peer's CA-verified certificate when available at the
// lookup site. The responder always passes a non-nil cert (parsed from
// msg1 before this lookup fires); the initiator passes whatever cached
// cert it has (from the host map or pq.Store), or nil on a first-contact
// boot. Implementations that wrap a Provider with cert-extension
// validation (see pq.NewValidatingPSKLookup) use peerCert to cross-check
// the peer's PQ-PSK binding extension against the provider's per-peer
// binding hint and may return nil to refuse the PSK under enforce
// mode. A nil cert is treated as "no claim to verify".
type PSKLookupFunc func(peerStaticPubKey []byte, peerCert cert.Certificate) []byte

// Credential holds everything needed to participate in a handshake
// at a given cert version. Version and Curve are read from Cert; the public
// half of the static keypair likewise comes from Cert.PublicKey().
type Credential struct {
	Cert            cert.Certificate  // the certificate
	Bytes           []byte            // pre-marshaled certificate bytes
	privateKey      []byte            // static private key (public half lives in Cert)
	cipherSuite     noise.CipherSuite // pre-built cipher suite (DH + cipher + hash)
	pqPSKLookup     PSKLookupFunc     // optional; nil disables PQ PSK entirely
	pqPSKLookupPrev PSKLookupFunc     // optional; previous-epoch fallback for skew healing
}

// NewCredential creates a Credential with all material needed for handshake
// participation. The cipherSuite should be pre-built by the caller with the
// appropriate DH function, cipher, and hash. pqPSKLookup, if non-nil, is
// consulted by the handshake machinery to fetch a 32-byte PSK keyed by peer
// static public key. Pass nil to disable PSK behaviour entirely.
func NewCredential(
	c cert.Certificate,
	hsBytes []byte,
	privateKey []byte,
	cipherSuite noise.CipherSuite,
	pqPSKLookup PSKLookupFunc,
) *Credential {
	return &Credential{
		Cert:        c,
		Bytes:       hsBytes,
		privateKey:  privateKey,
		cipherSuite: cipherSuite,
		pqPSKLookup: pqPSKLookup,
	}
}

// LookupPSK returns the configured PSK for the given peer's static public
// key, or nil if none is configured (or if no lookup function was set).
// This is exposed so the responder Machine can call it after parsing the
// initiator's static key out of msg1, before producing msg2 with the PSK
// mixed in at placement 2.
//
// peerCert is forwarded verbatim to the underlying PSKLookupFunc; pass
// the verified peer cert when available so cert-extension binding
// checks (the PQ-PSK binding extension) can run, or nil when no cert
// is in hand yet.
func (hc *Credential) LookupPSK(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
	if hc.pqPSKLookup == nil {
		return nil
	}
	return hc.pqPSKLookup(peerStaticPubKey, peerCert)
}

// SetPSKLookupPrev installs the previous-epoch PSK lookup. Optional:
// when nil (default), epoch-skew healing is simply unavailable and
// handshakes behave exactly as before.
func (hc *Credential) SetPSKLookupPrev(fn PSKLookupFunc) { hc.pqPSKLookupPrev = fn }

// LookupPSKPrev returns the previous-epoch PSK for the peer, or nil.
func (hc *Credential) LookupPSKPrev(peerStaticPubKey []byte, peerCert cert.Certificate) []byte {
	if hc.pqPSKLookupPrev == nil {
		return nil
	}
	return hc.pqPSKLookupPrev(peerStaticPubKey, peerCert)
}

// buildHandshakeState creates a noise.HandshakeState from this credential.
//
// placement maps to noise.Config.PresharedKeyPlacement. peerStaticPubKey is
// used only by the initiator side at placement >= 2 to look up the PSK at
// config time; responders pass nil and call hs.SetPresharedKey via
// LookupPSK after reading the initiator's static key from msg1.
//
// peerCert is the peer's cached cert (if any) at PSK-config time on the
// initiator side. Forwarded to PSKLookupFunc so cert-extension binding
// validation (the PQ-PSK binding extension) can refuse the PSK before
// any wire bytes are produced. Pass nil when no cached cert is
// available — the
// lookup wrapper treats that as "no claim to verify" and falls through
// to the same answer the legacy two-arg lookup would have given.
//
// If a PSK is configured but lookup fails (returns nil), placement-2
// initiator construction errors out — refusing to send a handshake without
// a PSK is part of the all-or-nothing guarantee for v1.
func (hc *Credential) buildHandshakeState(
	initiator bool,
	pattern noise.HandshakePattern,
	placement int,
	peerStaticPubKey []byte,
	peerCert cert.Certificate,
) (*noise.HandshakeState, error) {
	var psk []byte
	if hc.pqPSKLookup != nil {
		switch placement {
		case 0:
			// Mesh-wide PSK mode (v0). Lookup is keyed by nil; the
			// implementation should ignore the argument and return
			// the single mesh-wide PSK. peerCert is irrelevant for
			// mesh-wide PSKs (no per-peer binding claim).
			psk = hc.pqPSKLookup(nil, nil)
		case 2:
			if initiator {
				if peerStaticPubKey == nil {
					return nil, errors.New("initiator at psk placement 2 requires peer static pubkey")
				}
				psk = hc.pqPSKLookup(peerStaticPubKey, peerCert)
				if psk == nil {
					return nil, fmt.Errorf("no psk configured for peer %x", peerStaticPubKey)
				}
				// flynn/noise enforces 32 bytes too, but its error doesn't
				// say where the bad key came from. A non-nil wrong-length
				// slice (e.g. a lookup returning []byte{} on a miss
				// instead of nil) should blame the provider explicitly.
				if len(psk) != 32 {
					return nil, fmt.Errorf("psk lookup for peer %x returned %d bytes, want 32", peerStaticPubKey, len(psk))
				}
			}
			// Responder: leave psk nil here. flynn/noise still
			// activates psk2 because PresharedKeyPlacement >= 2,
			// regardless of an empty PresharedKey at config time.
			// The Machine sets the actual key with SetPresharedKey
			// once it has read the peer's static from msg1.
		}
	}
	// psk2 initiator: route the key through SetPresharedKey explicitly
	// (noise copies either way — Config.PresharedKey is also installed
	// via SetPresharedKey internally) so OUR transient lookup copy has
	// a single, obvious owner and can be wiped immediately after
	// installation. placement-0 keys stay in the Config — noise needs
	// them at construction for the first message — and are long-lived
	// mesh-wide values we don't own, so no wipe there.
	var configPSK []byte
	installAfter := false
	switch {
	case placement == 2 && initiator && len(psk) > 0:
		configPSK = nil
		installAfter = true
	default:
		configPSK = psk
	}
	if configPSK == nil {
		configPSK = []byte{}
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           hc.cipherSuite,
		Random:                rand.Reader,
		Pattern:               pattern,
		Initiator:             initiator,
		StaticKeypair:         noise.DHKey{Private: hc.privateKey, Public: hc.Cert.PublicKey()},
		PresharedKey:          configPSK,
		PresharedKeyPlacement: placement,
	})
	if err != nil {
		return nil, err
	}
	if installAfter {
		if err := hs.SetPresharedKey(psk); err != nil {
			return nil, err
		}
		wipeBytes(psk)
	}
	return hs, nil
}

// wipeBytes best-effort zeroes transient key material; twin of
// pq.Wipe, duplicated to keep package handshake free of a pq import.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetCredentialFunc returns the handshake credential for the given version,
// or nil if that version is not available.
//
// Implementations must return credentials drawn from a snapshot stable for
// the lifetime of any single Machine. The Machine may call this multiple
// times during a handshake (e.g. when negotiating to the peer's version)
// and assumes the underlying static keypair is consistent across calls.
type GetCredentialFunc func(v cert.Version) *Credential
