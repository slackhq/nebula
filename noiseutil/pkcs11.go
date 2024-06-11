package noiseutil

import (
	"crypto/ecdh"
	"fmt"
	"strings"

	"github.com/slackhq/nebula/pkclient"

	"github.com/flynn/noise"
)

// DHP256PKCS11 is the NIST P-256 ECDH function
var DHP256PKCS11 noise.DHFunc = newNISTP11Curve("P256", ecdh.P256(), 32)

type nistP11Curve struct {
	nistCurve
}

func newNISTP11Curve(name string, curve ecdh.Curve, byteLen int) nistP11Curve {
	return nistP11Curve{
		newNISTCurve(name, curve, byteLen),
	}
}

func (c nistP11Curve) DH(privkey, pubkey []byte) ([]byte, error) {
	//for this function "privkey" is actually a pkcs11 URI
	pkStr := string(privkey)

	//to set up a handshake, we need to also do non-pkcs11-DH. Handle that here.
	if !strings.HasPrefix(pkStr, "pkcs11:") {
		return DHP256.DH(privkey, pubkey)
	}
	ecdhPubKey, err := c.curve.NewPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal pubkey: %w", err)
	}

	//this is not the most performant way to do this (a long-lived client would be better)
	//but, it works, and helps avoid problems with stale sessions and HSMs used by multiple users.
	client, err := pkclient.FromUrl(pkStr)
	if err != nil {
		return nil, err
	}
	defer func(client *pkclient.PKClient) {
		_ = client.Close()
	}(client)

	return client.DeriveNoise(ecdhPubKey.Bytes())
}
