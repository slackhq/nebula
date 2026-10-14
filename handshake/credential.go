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
	kemKey      noise.KEMKey      // static ML-KEM-1024 keypair, only for a v3 Cert
	cipherSuite noise.CipherSuite // pre-built cipher suite (DH + cipher + hash)
}

// NewCredential creates a Credential with all material needed for handshake
// participation. The cipherSuite should be pre-built by the caller with the
// appropriate DH function, cipher, and hash.
//
// For a version 3 certificate privateKey is the composite private key,
// classical || ML-KEM-1024 seed, matching the composite Cert.PublicKey().
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
	if v2 := cert.V2Form(c); v2 != nil {
		classical := v2.PublicKey()
		hc.publicKey = classical
		hc.kemKey = noise.KEMKey{
			Private: privateKey[len(privateKey)-cert.MLKEM1024PrivateKeySize:],
			Public:  c.PublicKey()[len(classical):],
		}
		hc.privateKey = privateKey[:len(privateKey)-cert.MLKEM1024PrivateKeySize]
	}
	return hc
}

// buildHandshakeState creates a noise.HandshakeState from this credential.
// pskPlacement selects the noise psk modifier; 0 means none. A psk for
// placements 2 and up is supplied later with SetPresharedKey. A hybrid
// pattern also gets ML-KEM-1024 and the static ML-KEM key.
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
	if info.hybrid {
		cfg.KEMFunc = KEMMLKEM1024
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
