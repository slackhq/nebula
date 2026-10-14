package handshake

import (
	"crypto/rand"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/cert"
)

// Credential holds everything needed to participate in a handshake
// at a given cert version. Version and Curve are read from Cert; the public
// half of the static keypair likewise comes from Cert.PublicKey().
type Credential struct {
	Cert        cert.Certificate  // the certificate
	Bytes       []byte            // pre-marshaled certificate bytes
	privateKey  []byte            // static private key (public half lives in Cert)
	publicKey   []byte            // static public key, the classical half for a v3 Cert
	kemKey      noise.KEMKey      // static KEM keypair of the Cert's suite, only for a v3 Cert
	cipherSuite noise.CipherSuite // pre-built cipher suite (DH + cipher + hash)
}

// NewCredential creates a Credential with all material needed for handshake
// participation. The cipherSuite should be pre-built by the caller with the
// appropriate DH function, cipher, and hash.
//
// For a version 3 certificate privateKey is the composite private key,
// classical || the seed of its suite's KEM, matching the composite
// Cert.PublicKey().
func NewCredential(
	c cert.Certificate,
	hsBytes []byte,
	privateKey []byte,
	cipherSuite noise.CipherSuite,
) *Credential {
	hc := &Credential{
		Cert:        c,
		Bytes:       hsBytes,
		privateKey:  privateKey,
		publicKey:   c.PublicKey(),
		cipherSuite: cipherSuite,
	}
	if suite := cert.PQSuiteOf(c); suite != cert.PQSuiteUnknown {
		// The pki checked the private key against the certificate, so both split.
		hc.publicKey, hc.kemKey.Public, _ = suite.SplitPublicKey(false, c.PublicKey())
		hc.privateKey, hc.kemKey.Private, _ = suite.SplitPrivateKey(false, privateKey)
	}
	return hc
}

// buildHandshakeState creates a noise.HandshakeState from this credential.
// pskPlacement selects the noise psk modifier; 0 means none. A psk for
// placements 2 and up is supplied later with SetPresharedKey. A hybrid
// pattern also gets its KEM and the static KEM key.
func (hc *Credential) buildHandshakeState(initiator bool, info subtypeInfo) (*noise.HandshakeState, error) {
	cfg := noise.Config{
		CipherSuite:           hc.cipherSuite,
		Random:                rand.Reader,
		Pattern:               info.pattern,
		Initiator:             initiator,
		StaticKeypair:         noise.DHKey{Private: hc.privateKey, Public: hc.publicKey},
		PresharedKey:          []byte{},
		PresharedKeyPlacement: info.pskPlacement,
	}
	if info.kem != nil {
		cfg.KEMFunc = info.kem
		cfg.StaticKEMKeypair = hc.kemKey
	}
	return noise.NewHandshakeState(cfg)
}

// GetCredentialFunc returns the handshake credential for the given version,
// or nil if that version is not available.
//
// Implementations must return credentials drawn from a snapshot stable for
// the lifetime of any single Machine. The Machine may call this multiple
// times during a handshake (e.g. when negotiating to the peer's version)
// and assumes the underlying static keypair is consistent across calls.
type GetCredentialFunc func(v cert.Version) *Credential
