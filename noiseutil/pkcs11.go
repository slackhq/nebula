package noiseutil

import (
	"crypto/ecdh"
	"fmt"
	"strings"
	"sync"

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

// Cache one long-lived client per pkcs11 URI. PKCS#11 sessions are not safe
// for concurrent operations, so each client's derives are serialized under its
// own mutex, which also matches the token, which serializes regardless. A
// derive error (stale session after a token reset / re-init) drops the cached
// client so the next handshake transparently re-opens it.
type p11Client struct {
	mu     sync.Mutex
	client *pkclient.PKClient
}

var (
	p11mu    sync.Mutex
	p11cache = map[string]*p11Client{}
)

func getP11Client(uri string) *p11Client {
	p11mu.Lock()
	defer p11mu.Unlock()
	c := p11cache[uri]
	if c == nil {
		c = &p11Client{}
		p11cache[uri] = c
	}
	return c
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

	pc := getP11Client(pkStr)
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.client == nil {
		pc.client, err = pkclient.FromUrl(pkStr)
		if err != nil {
			return nil, err
		}
	}

	out, err := pc.client.DeriveNoise(ecdhPubKey.Bytes())
	if err != nil {
		// The session may be stale (token reset / re-init). Drop it so the
		// next handshake re-opens a fresh client.
		_ = pc.client.Close()
		pc.client = nil
		return nil, err
	}
	return out, nil
}
