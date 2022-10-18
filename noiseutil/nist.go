package noiseutil

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"

	"github.com/flynn/noise"
)

// DHP256 is the NIST P-256 ECDH function
var DHP256 noise.DHFunc = newNISTCurve("P256", elliptic.P256())

type nistCurve struct {
	name   string
	curve  elliptic.Curve
	dhLen  int
	pubLen int
}

func newNISTCurve(name string, curve elliptic.Curve) nistCurve {
	byteLen := (curve.Params().BitSize + 7) / 8
	return nistCurve{
		name:  name,
		curve: curve,
		dhLen: byteLen,
		// Standard uncompressed format, type (1 byte) plus both coordinates
		pubLen: 1 + 2*byteLen,
	}
}

func (c nistCurve) GenerateKeypair(rng io.Reader) (noise.DHKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	privkey, x, y, err := elliptic.GenerateKey(c.curve, rng)
	if err != nil {
		return noise.DHKey{}, err
	}
	pubkey := elliptic.Marshal(c.curve, x, y)
	return noise.DHKey{Private: privkey, Public: pubkey}, nil
}

func (c nistCurve) DH(privkey, pubkey []byte) ([]byte, error) {
	// based on stdlib crypto/tls/key_schedule.go
	// - https://github.com/golang/go/blob/go1.19/src/crypto/tls/key_schedule.go#L167-L178
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(c.curve, pubkey)
	if x == nil {
		return nil, errors.New("unable to unmarshal pubkey")
	}

	xShared, _ := c.curve.ScalarMult(x, y, privkey)
	sharedKey := make([]byte, c.dhLen)
	return xShared.FillBytes(sharedKey), nil
}

func (c nistCurve) DHLen() int {
	// NOTE: Noise Protocol specifies "DHLen" to represent two things:
	// - The size of the public key
	// - The return size of the DH() function
	// But for standard NIST ECDH, the sizes of these are different.
	// Luckily, the flynn/noise library actually only uses this DHLen()
	// value to represent the public key size, so that is what we are
	// returning here. The length of the DH() return bytes are unaffected by
	// this value here.
	return c.pubLen
}
func (c nistCurve) DHName() string { return c.name }
