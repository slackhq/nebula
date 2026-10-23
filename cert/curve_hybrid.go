package cert

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Curve_P384_MLKEM1024_MLDSA87 is the hybrid curve, for version 2 certificates only, which is why it is defined here
// rather than in cert_v1.proto. A host key agrees on keys with P-384 ECDH and ML-KEM-1024, the pairing
// draft-ietf-tls-ecdhe-mlkem calls SecP384r1MLKEM1024. A CA key signs with the composite of ML-DSA-87 and ECDSA P-384,
// id-MLDSA87-ECDSA-P384-SHA512 of draft-ietf-lamps-pq-composite-sigs. Every algorithm is in CNSA 1.0 or 2.0.
const Curve_P384_MLKEM1024_MLDSA87 Curve = 2

// CurveName returns the name of a curve, the hybrid one included, which the generated Curve.String does not know.
func CurveName(c Curve) string {
	if c == Curve_P384_MLKEM1024_MLDSA87 {
		return "P384_MLKEM1024_MLDSA87"
	}
	return c.String()
}

// Sizes of the hybrid curve's keys and signatures. Public keys and signatures are laid out as their specifications say,
// so draft-ietf-lamps-pq-composite-sigs test vectors apply; private keys are nebula's own, raw scalars as for P256.
const (
	p384PointSize  = 97 // uncompressed
	p384ScalarSize = 48

	// MLKEM1024PublicKeySize is the size of an ML-KEM-1024 encapsulation key.
	MLKEM1024PublicKeySize = mlkem.EncapsulationKeySize1024
	// MLKEM1024SeedSize is the size of an ML-KEM-1024 decapsulation key seed.
	MLKEM1024SeedSize = mlkem.SeedSize
	// MLDSA87PublicKeySize is the size of an ML-DSA-87 public key.
	MLDSA87PublicKeySize = mldsa.MLDSA87PublicKeySize
	// MLDSA87SeedSize is the size of an ML-DSA-87 private key seed.
	MLDSA87SeedSize = mldsa.PrivateKeySize
	// MLDSA87SignatureSize is the size of an ML-DSA-87 signature.
	MLDSA87SignatureSize = mldsa.MLDSA87SignatureSize

	// HybridPublicKeySize is a host's public key: the P-384 point followed by the ML-KEM-1024 encapsulation key, the
	// order of SecP384r1MLKEM1024 in draft-ietf-tls-ecdhe-mlkem.
	HybridPublicKeySize = p384PointSize + MLKEM1024PublicKeySize
	// HybridPrivateKeySize is a host's private key: the P-384 scalar followed by the ML-KEM-1024 seed.
	HybridPrivateKeySize = p384ScalarSize + MLKEM1024SeedSize
	// HybridSigningPublicKeySize is a CA's public key: the ML-DSA-87 key followed by the P-384 point, as
	// draft-ietf-lamps-pq-composite-sigs serializes a composite key (§4.1).
	HybridSigningPublicKeySize = MLDSA87PublicKeySize + p384PointSize
	// HybridSigningPrivateKeySize is a CA's private key: the ML-DSA-87 seed followed by the P-384 scalar, the order of
	// §4.2, with the scalar raw rather than an RFC 5915 ECPrivateKey.
	HybridSigningPrivateKeySize = MLDSA87SeedSize + p384ScalarSize
)

// The composite signature, id-MLDSA87-ECDSA-P384-SHA512 of draft-ietf-lamps-pq-composite-sigs-19, with an empty ctx.
const (
	compositePrefix = "CompositeAlgorithmSignatures2025"
	compositeLabel  = "COMPSIG-MLDSA87-ECDSA-P384-SHA512"
)

// hybridAvailable is nil when this build has ML-DSA and ML-KEM. The FIPS 140-3 Go Cryptographic Module v1.0.0 has no
// ML-DSA, and every call of it fails.
var hybridAvailable = sync.OnceValue(func() error {
	if _, err := mlkem.NewDecapsulationKey1024(make([]byte, mlkem.SeedSize)); err != nil {
		return fmt.Errorf("%w: %w", ErrPQUnavailable, err)
	}
	if _, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), make([]byte, mldsa.PrivateKeySize)); err != nil {
		return fmt.Errorf("%w: %w", ErrPQUnavailable, err)
	}
	return nil
})

// HybridAvailable returns an error wrapping ErrPQUnavailable, and the algorithm's own, when this build can not run the
// hybrid curve, as under the FIPS 140-3 Go Cryptographic Module v1.0.0, which has no ML-DSA.
func HybridAvailable() error {
	return hybridAvailable()
}

// compositeMessage returns M' of draft-ietf-lamps-pq-composite-sigs §2.2 for message m and an empty ctx:
// Prefix || Label || len(ctx) || ctx || SHA-512(m).
func compositeMessage(m []byte) []byte {
	sum := sha512.Sum512(m)
	out := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(sum))
	out = append(out, compositePrefix...)
	out = append(out, compositeLabel...)
	out = append(out, 0)
	return append(out, sum[:]...)
}

// compositeVerify checks a composite signature, mldsaSig || ecdsaSig, of m by a composite public key,
// mldsaPK || P-384 point. Both halves must verify, and the ECDSA one must be low-s: nothing else covers it, and its
// high-s twin would give the certificate a second fingerprint.
func compositeVerify(pk, m, sig []byte) bool {
	if len(pk) != HybridSigningPublicKeySize || len(sig) <= MLDSA87SignatureSize {
		return false
	}
	mldsaPK, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pk[:MLDSA87PublicKeySize])
	if err != nil {
		return false
	}
	ecPK, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pk[MLDSA87PublicKeySize:])
	if err != nil {
		return false
	}
	mldsaSig, ecSig := sig[:MLDSA87SignatureSize], sig[MLDSA87SignatureSize:]
	if !p384LowS(ecSig) {
		return false
	}
	mp := compositeMessage(m)
	if mldsa.Verify(mldsaPK, mp, mldsaSig, &mldsa.Options{Context: compositeLabel}) != nil {
		return false
	}
	h := sha512.Sum384(mp)
	return ecdsa.VerifyASN1(ecPK, h[:], ecSig)
}

// compositeSigner returns a SignerLambda that signs messages with a composite private key, mldsaSeed || P-384 scalar,
// as id-MLDSA87-ECDSA-P384-SHA512: ML-DSA-87 over M' with the label as its context, then ECDSA P-384 with SHA-384 over
// M'. SignWith brings the ECDSA signature to low-s, as it does for any signer.
func compositeSigner(sk []byte) (SignerLambda, error) {
	if len(sk) != HybridSigningPrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	mldsaSK, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), sk[:MLDSA87SeedSize])
	if err != nil {
		return nil, err
	}
	ecSK, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), sk[MLDSA87SeedSize:])
	if err != nil {
		return nil, err
	}
	return func(m []byte) ([]byte, error) {
		mp := compositeMessage(m)
		mldsaSig, err := mldsaSK.Sign(rand.Reader, mp, &mldsa.Options{Context: compositeLabel})
		if err != nil {
			return nil, err
		}
		h := sha512.Sum384(mp)
		ecSig, err := ecSK.Sign(rand.Reader, h[:], crypto.SHA384)
		if err != nil {
			return nil, err
		}
		return append(mldsaSig, ecSig...), nil
	}, nil
}

// hybridSigningPublicKey derives a CA's composite public key from its private key.
func hybridSigningPublicKey(sk []byte) ([]byte, error) {
	if len(sk) != HybridSigningPrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	mldsaSK, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), sk[:MLDSA87SeedSize])
	if err != nil {
		return nil, err
	}
	ecSK, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), sk[MLDSA87SeedSize:])
	if err != nil {
		return nil, err
	}
	point, err := ecSK.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return append(mldsaSK.PublicKey().Bytes(), point...), nil
}

// hybridPublicKey derives a host's public key from its private key.
func hybridPublicKey(sk []byte) ([]byte, error) {
	if len(sk) != HybridPrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	ecSK, err := ecdh.P384().NewPrivateKey(sk[:p384ScalarSize])
	if err != nil {
		return nil, err
	}
	dk, err := mlkem.NewDecapsulationKey1024(sk[p384ScalarSize:])
	if err != nil {
		return nil, err
	}
	return append(ecSK.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()...), nil
}

// checkHybridPublicKey reports whether a host's or CA's public key is well formed.
func checkHybridPublicKey(isCA bool, pk []byte) bool {
	if isCA {
		if len(pk) != HybridSigningPublicKeySize {
			return false
		}
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pk[:MLDSA87PublicKeySize]); err != nil {
			return false
		}
		_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pk[MLDSA87PublicKeySize:])
		return err == nil
	}
	if len(pk) != HybridPublicKeySize {
		return false
	}
	if _, err := ecdh.P384().NewPublicKey(pk[:p384PointSize]); err != nil {
		return false
	}
	_, err := mlkem.NewEncapsulationKey1024(pk[p384PointSize:])
	return err == nil
}

// GenerateHybridKeypair makes a host keypair of the hybrid curve.
func GenerateHybridKeypair() (pub, priv []byte, err error) {
	ecSK, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	pub = append(ecSK.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()...)
	priv = append(ecSK.Bytes(), dk.Bytes()...)
	return pub, priv, nil
}

// GenerateHybridSigningKeypair makes a CA keypair of the hybrid curve.
func GenerateHybridSigningKeypair() (pub, priv []byte, err error) {
	mldsaSK, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, err
	}
	ecSK, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	point, err := ecSK.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}
	scalar, err := ecSK.Bytes()
	if err != nil {
		return nil, nil, err
	}
	pub = append(mldsaSK.PublicKey().Bytes(), point...)
	priv = append(mldsaSK.Bytes(), scalar...)
	return pub, priv, nil
}

// SplitHybridPublicKey splits a host's public key into its P-384 point and ML-KEM-1024 encapsulation key.
func SplitHybridPublicKey(pk []byte) (point, ek []byte, err error) {
	if len(pk) != HybridPublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}
	return pk[:p384PointSize], pk[p384PointSize:], nil
}

// SplitHybridPrivateKey splits a host's private key into its P-384 scalar and ML-KEM-1024 seed.
func SplitHybridPrivateKey(sk []byte) (scalar, seed []byte, err error) {
	if len(sk) != HybridPrivateKeySize {
		return nil, nil, ErrInvalidPrivateKey
	}
	return sk[:p384ScalarSize], sk[p384ScalarSize:], nil
}

// compositeNormalize returns a composite signature with its ECDSA half in the low-s form. The composite signature
// allows either, and the draft's own test vector is high-s, so a signer outside nebula may well produce one.
func compositeNormalize(sig []byte) ([]byte, error) {
	if len(sig) <= MLDSA87SignatureSize {
		return nil, fmt.Errorf("composite signature too short: %d bytes", len(sig))
	}
	ecSig, err := p384Normalize(sig[MLDSA87SignatureSize:])
	if err != nil {
		return nil, err
	}
	return append(sig[:MLDSA87SignatureSize:MLDSA87SignatureSize], ecSig...), nil
}

var p384HalfN = new(big.Int).Rsh(elliptic.P384().Params().N, 1)

// p384LowS reports whether an ASN.1 ECDSA P-384 signature is in its low-s form, s <= N/2.
func p384LowS(sig []byte) bool {
	_, s, err := parseECDSASignature(sig)
	return err == nil && s.Cmp(p384HalfN) <= 0
}

// p384Normalize returns an ASN.1 ECDSA P-384 signature in its low-s form.
func p384Normalize(sig []byte) ([]byte, error) {
	r, s, err := parseECDSASignature(sig)
	if err != nil {
		return nil, err
	}
	if s.Cmp(p384HalfN) <= 0 {
		return sig, nil
	}
	s.Sub(elliptic.P384().Params().N, s)
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

func parseECDSASignature(sig []byte) (r, s *big.Int, err error) {
	r, s = new(big.Int), new(big.Int)
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() || !inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}
