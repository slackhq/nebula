package p256

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"filippo.io/bigmod"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var halfN = new(big.Int).Rsh(elliptic.P256().Params().N, 1)
var nMod *bigmod.Modulus

func init() {
	n, err := bigmod.NewModulus(elliptic.P256().Params().N.Bytes())
	if err != nil {
		panic(err)
	}
	nMod = n
}

func IsNormalized(sig []byte) (bool, error) {
	r, s, err := parseSignature(sig)
	if err != nil {
		return false, err
	}
	return checkLowS(r, s), nil
}

func checkLowS(_, s []byte) bool {
	bigS := new(big.Int).SetBytes(s)
	// Check if S <= (N/2), because we want to include the midpoint in the set of low-s
	return bigS.Cmp(halfN) <= 0
}

func swap(r, s []byte) ([]byte, []byte, error) {
	var err error
	bigS, err := bigmod.NewNat().SetBytes(s, nMod)
	if err != nil {
		return nil, nil, err
	}
	sNormalized := nMod.Nat().Sub(bigS, nMod)

	return r, sNormalized.Bytes(nMod), nil
}

func Normalize(sig []byte) ([]byte, error) {
	r, s, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}

	if checkLowS(r, s) {
		return sig, nil
	}

	newR, newS, err := swap(r, s)
	if err != nil {
		return nil, err
	}

	return encodeSignature(newR, newS)
}

// Swap will change sig between its current form to the opposite high or low form.
func Swap(sig []byte) ([]byte, error) {
	r, s, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}

	newR, newS, err := swap(r, s)
	if err != nil {
		return nil, err
	}

	return encodeSignature(newR, newS)
}

// parseSignature taken exactly from crypto/ecdsa/ecdsa.go
func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}
