package noiseutil

import (
	"crypto/ecdh"
	"fmt"
	"net/url"
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

// Normalizes a PKCS#11 URI, removing all Nebula-specific parameters.
// Returns the normalized URI (if it parses successfully), a boolean indicating
// whether this session should be cached, and an optional error.
func normalizeP11Uri(uri string) (string, bool, error) {
	parsedUri, err := url.Parse(uri)
	cache := true

	if parsedUri != nil && err == nil {
		query := parsedUri.Query()

		// Ensure that we delete keys here, or else we get a
		// "malformed query attribute" error from PKClient.
		if query.Has("cache-sessions") {
			cacheSessions := query.Get("cache-sessions")
			if cacheSessions == "0" {
				cache = false
			} else if cacheSessions == "" || cacheSessions == "1" {
				cache = true
			} else {
				return uri, cache, fmt.Errorf("invalid value for cache-sessions: %v", cacheSessions)
			}
			query.Del("cache-sessions")
		}

		parsedUri.RawQuery = query.Encode()
		return parsedUri.String(), cache, nil
	} else {
		return uri, cache, fmt.Errorf("bad URI: %w", err)
	}
}

// Returns a PKCS#11 client from the specified URI, possibly caching it.
// Returns (client, final URI, true if it was cached, error).
func getP11Client(uri string) (*p11Client, string, bool, error) {
	normalizedUri, cache, err := normalizeP11Uri(uri)

	if err != nil {
		return nil, normalizedUri, cache, fmt.Errorf("unable to parse PKCS#11 URI: %w", err)
	}

	var c *p11Client = nil
	if cache {
		p11mu.Lock()
		defer p11mu.Unlock()
		c = p11cache[normalizedUri]
		if c == nil {
			c = &p11Client{}
			p11cache[normalizedUri] = c
		}
	} else {
		c = &p11Client{}
	}

	return c, normalizedUri, cache, nil
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

	pc, uri, cache, err := getP11Client(pkStr)

	if err != nil {
		return nil, fmt.Errorf("unable to get PKCS#11 client: %w", err)
	}

	if cache {
		pc.mu.Lock()
		defer pc.mu.Unlock()
	}

	if pc.client == nil {
		pc.client, err = pkclient.FromUrl(uri)
		if err != nil {
			return nil, err
		}
	}

	out, err := pc.client.DeriveNoise(ecdhPubKey.Bytes())
	if err != nil || !cache {
		// The session may be stale (token reset / re-init). Drop it so the
		// next handshake re-opens a fresh client.
		_ = pc.client.Close()
		pc.client = nil
	}
	return out, err
}
