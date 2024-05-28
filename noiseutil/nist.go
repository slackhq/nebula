package noiseutil

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// DHP256 is the NIST P-256 ECDH function
var DHP256 noise.DHFunc = newNISTCurve("P256", ecdh.P256(), 32)

type nistCurve struct {
	name   string
	curve  ecdh.Curve
	dhLen  int
	pubLen int
}

func newNISTCurve(name string, curve ecdh.Curve, byteLen int) nistCurve {
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
	privkey, err := c.curve.GenerateKey(rng)
	if err != nil {
		return noise.DHKey{}, err
	}
	pubkey := privkey.PublicKey()
	return noise.DHKey{Private: privkey.Bytes(), Public: pubkey.Bytes()}, nil
}

func (c nistCurve) DH(privkey, pubkey []byte) ([]byte, error) {
	ecdhPubKey, err := c.curve.NewPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal pubkey: %w", err)
	}
	ecdhPrivKey, err := c.curve.NewPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal private key: %w", err)
	}

	return ecdhPrivKey.ECDH(ecdhPubKey)
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
