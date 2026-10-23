package cert

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
)

// Curve_MLKEM1024_MLDSA87 is the post-quantum curve, for version 2 certificates only: a host key agrees on keys with
// ML-KEM-1024 and a CA key signs with ML-DSA-87, CNSA 2.0's algorithms and no others. Unlike the hybrid curve it has
// no classical half to fall back on should a post-quantum algorithm fall.
const Curve_MLKEM1024_MLDSA87 Curve = 3

// Sizes of the post-quantum curve's keys. A host's public key is the ML-KEM-1024 encapsulation key and its private key
// the 64 byte seed; a CA's public key is the ML-DSA-87 key and its private key the 32 byte seed. A signature is an
// ML-DSA-87 signature.
const (
	PurePublicKeySize         = MLKEM1024PublicKeySize
	PurePrivateKeySize        = MLKEM1024SeedSize
	PureSigningPublicKeySize  = MLDSA87PublicKeySize
	PureSigningPrivateKeySize = MLDSA87SeedSize
)

// pureContext is the ML-DSA context string of a certificate signature on the post-quantum curve. It keeps a CA's
// signatures of nebula certificates apart from anything else its key might ever sign.
const pureContext = "nebula certificate"

// IsPostQuantum reports whether curve is one of the post-quantum curves, the hybrid one or the pure one. Their
// fingerprints are SHA-512, and they make three message post-quantum handshakes.
func IsPostQuantum(curve Curve) bool {
	return curve == Curve_P384_MLKEM1024_MLDSA87 || curve == Curve_MLKEM1024_MLDSA87
}

// pureVerify checks an ML-DSA-87 signature of m by an ML-DSA-87 public key.
func pureVerify(pk, m, sig []byte) bool {
	if len(pk) != PureSigningPublicKeySize || len(sig) != MLDSA87SignatureSize {
		return false
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pk)
	if err != nil {
		return false
	}
	return mldsa.Verify(key, m, sig, &mldsa.Options{Context: pureContext}) == nil
}

// pureSigner returns a SignerLambda that signs messages with an ML-DSA-87 private key seed, hedged as FIPS 204
// recommends.
func pureSigner(sk []byte) (SignerLambda, error) {
	if len(sk) != PureSigningPrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), sk)
	if err != nil {
		return nil, err
	}
	return func(m []byte) ([]byte, error) {
		return key.Sign(rand.Reader, m, &mldsa.Options{Context: pureContext})
	}, nil
}

// pureSigningPublicKey derives a CA's ML-DSA-87 public key from its private key.
func pureSigningPublicKey(sk []byte) ([]byte, error) {
	if len(sk) != PureSigningPrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), sk)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// purePublicKey derives a host's ML-KEM-1024 encapsulation key from its private key.
func purePublicKey(sk []byte) ([]byte, error) {
	if len(sk) != PurePrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	dk, err := mlkem.NewDecapsulationKey1024(sk)
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}

// checkPurePublicKey reports whether a host's or CA's public key on the post-quantum curve is well formed.
func checkPurePublicKey(isCA bool, pk []byte) bool {
	if isCA {
		if len(pk) != PureSigningPublicKeySize {
			return false
		}
		_, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pk)
		return err == nil
	}
	if len(pk) != PurePublicKeySize {
		return false
	}
	_, err := mlkem.NewEncapsulationKey1024(pk)
	return err == nil
}

// GeneratePureKeypair makes a host keypair of the post-quantum curve.
func GeneratePureKeypair() (pub, priv []byte, err error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

// GeneratePureSigningKeypair makes a CA keypair of the post-quantum curve.
func GeneratePureSigningKeypair() (pub, priv []byte, err error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, err
	}
	return key.PublicKey().Bytes(), key.Bytes(), nil
}
