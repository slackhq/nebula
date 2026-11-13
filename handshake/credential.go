package handshake

import (
	"crypto/mlkem"
	"crypto/rand"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/cert"
)

// Credential holds everything needed to participate in a handshake
// at a given cert version. Version and Curve are read from Cert; the public
// half of the static keypair likewise comes from Cert.PublicKey().
type Credential struct {
	Cert        cert.Certificate            // the certificate
	Bytes       []byte                      // pre-marshaled certificate bytes
	privateKey  []byte                      // static private key, the P-384 half on the hybrid curve
	publicKey   []byte                      // static public key, the P-384 half on the hybrid curve
	kemKey      noise.KEMKey                // static ML-KEM-1024 keypair, only on the hybrid curve
	kemDK       *mlkem.DecapsulationKey1024 // kemKey expanded
	cipherSuite noise.CipherSuite           // pre-built cipher suite (DH + cipher + hash)
}

// NewCredential creates a Credential with all material needed for handshake
// participation. The cipherSuite should be pre-built by the caller with the
// appropriate DH function, cipher, and hash.
//
// On the hybrid curve privateKey is the host key, P-384 scalar || ML-KEM-1024
// seed, matching Cert.PublicKey().
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
	if c.Curve() == cert.Curve_P384_MLKEM1024_MLDSA87 {
		// The pki checked the private key against the certificate, so both split.
		hc.publicKey, hc.kemKey.Public, _ = cert.SplitHybridPublicKey(c.PublicKey())
		hc.privateKey, hc.kemKey.Private, _ = cert.SplitHybridPrivateKey(privateKey)
		// Expand the static KEM key once rather than in every handshake.
		hc.kemDK, _ = mlkem.NewDecapsulationKey1024(hc.kemKey.Private)
	}
	return hc
}

// buildHandshakeState creates a noise.HandshakeState from this credential. A
// hybrid pattern also gets its KEM and the static KEM key.
func (hc *Credential) buildHandshakeState(initiator bool, info subtypeInfo) (*noise.HandshakeState, error) {
	cfg := noise.Config{
		CipherSuite:   hc.cipherSuite,
		Random:        rand.Reader,
		Pattern:       info.pattern,
		Initiator:     initiator,
		StaticKeypair: noise.DHKey{Private: hc.privateKey, Public: hc.publicKey},
	}
	if info.kem != nil {
		cfg.KEMFunc = info.kem
		cfg.StaticKEMKeypair = hc.kemKey
		if info.kem == KEMMLKEM1024 {
			cfg.KEMFunc = &mlkem1024Keys{static: hc.kemDK, staticSeed: hc.kemKey.Private}
		}
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
