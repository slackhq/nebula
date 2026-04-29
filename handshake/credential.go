package handshake

import (
	"crypto/rand"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
)

// Credential holds everything needed to participate in a handshake
// at a given cert version. Version and Curve are read from Cert; the public
// half of the static keypair likewise comes from Cert.PublicKey().
type Credential struct {
	Cert        cert.Certificate  // the certificate
	Bytes       []byte            // pre-marshaled certificate bytes
	privateKey  []byte            // static private key (public half lives in Cert)
	cipherSuite noise.CipherSuite // pre-built cipher suite (DH + cipher + hash)
}

// NewCredential creates a Credential with all material needed for handshake
// participation. The cipherSuite should be pre-built by the caller with the
// appropriate DH function, cipher, and hash.
func NewCredential(
	c cert.Certificate,
	hsBytes []byte,
	privateKey []byte,
	cipherSuite noise.CipherSuite,
) *Credential {
	return &Credential{
		Cert:        c,
		Bytes:       hsBytes,
		privateKey:  privateKey,
		cipherSuite: cipherSuite,
	}
}

// buildHandshakeState creates a noise.HandshakeState from this credential.
func (hc *Credential) buildHandshakeState(initiator bool, pattern noise.HandshakePattern) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           hc.cipherSuite,
		Random:                rand.Reader,
		Pattern:               pattern,
		Initiator:             initiator,
		StaticKeypair:         noise.DHKey{Private: hc.privateKey, Public: hc.Cert.PublicKey()},
		PresharedKey:          []byte{},
		PresharedKeyPlacement: 0,
	})
}

// GetCredentialFunc returns the handshake credential for the given version,
// or nil if that version is not available.
//
// Implementations must return credentials drawn from a snapshot stable for
// the lifetime of any single Machine. The Machine may call this multiple
// times during a handshake (e.g. when negotiating to the peer's version)
// and assumes the underlying static keypair is consistent across calls.
type GetCredentialFunc func(v cert.Version) *Credential
