package nebula

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"golang.org/x/crypto/hkdf"
)

var ErrNotAPskMode = errors.New("not a psk mode")
var ErrKeyTooShort = errors.New("key is too short")
var ErrNotEnoughPskKeys = errors.New("at least 1 key is required")

// The minimum length that we accept for a user defined psk, the choice is arbitrary
const MinPskLength = 8

type PskMode int

func (p PskMode) String() string {
	switch p {
	case PskNone:
		return "none"
	case PskTransitional:
		return "transitional"
	case PskEnforced:
		return "enforced"
	}

	return "unknown"
}

func NewPskMode(m string) (PskMode, error) {
	switch m {
	case "none":
		return PskNone, nil
	case "transitional":
		return PskTransitional, nil
	case "enforced":
		return PskEnforced, nil
	}
	return PskNone, ErrNotAPskMode
}

const (
	PskNone         PskMode = 0
	PskTransitional PskMode = 1
	PskEnforced     PskMode = 2
)

type Psk struct {
	// pskMode sets how psk works, ignored, allowed for incoming, or enforced for all
	mode PskMode

	// Cache holds all pre-computed psk hkdfs
	// Handshakes iterate this directly
	Cache [][]byte

	// The key has already been extracted and is ready to be expanded for use
	// MakeFor does the final expand step mixing in the intended recipients vpn ip
	key []byte
}

// NewPskFromConfig is a helper for initial boot and config reloading.
func NewPskFromConfig(c *config.C, myVpnIp iputil.VpnIp) (*Psk, error) {
	sMode := c.GetString("handshakes.psk.mode", "none")
	mode, err := NewPskMode(sMode)
	if err != nil {
		return nil, NewContextualError("Could not parse handshakes.psk.mode", m{"mode": mode}, err)
	}

	return NewPsk(
		mode,
		c.GetStringSlice("handshakes.psk.keys", nil),
		myVpnIp,
	)
}

// NewPsk creates a new Psk object and handles the caching of all accepted keys and preparation of the primary key
func NewPsk(mode PskMode, keys []string, myVpnIp iputil.VpnIp) (*Psk, error) {
	psk := &Psk{
		mode: mode,
	}

	err := psk.preparePrimaryKey(keys)
	if err != nil {
		return nil, err
	}

	err = psk.cachePsks(myVpnIp, keys)
	if err != nil {
		return nil, err
	}

	return psk, nil
}

// MakeFor if we are in enforced mode, the final hkdf expand stage is done on the pre extracted primary key,
// mixing in the intended recipients vpn ip and the result is returned.
// If we are transitional or not using psks, an empty byte slice is returned
func (p *Psk) MakeFor(vpnIp iputil.VpnIp) ([]byte, error) {
	if p.mode != PskEnforced {
		return []byte{}, nil
	}

	hmacKey := make([]byte, sha256.Size)
	_, err := io.ReadFull(hkdf.Expand(sha256.New, p.key, vpnIp.ToIP()), hmacKey)
	if err != nil {
		return nil, err
	}

	return hmacKey, nil
}

// cachePsks generates all psks we accept and caches them to speed up handshaking
func (p *Psk) cachePsks(myVpnIp iputil.VpnIp, keys []string) error {
	// If PskNone is set then we are using the nil byte array for a psk, we can return
	if p.mode == PskNone {
		p.Cache = [][]byte{nil}
		return nil
	}

	if len(keys) < 1 {
		return ErrNotEnoughPskKeys
	}

	p.Cache = [][]byte{}

	if p.mode == PskTransitional {
		// We are transitional, we accept empty psks
		p.Cache = append(p.Cache, nil)
	}

	// We are either PskAuto or PskTransitional, build all possibilities
	for i, rk := range keys {
		k, err := sha256KdfFromString(rk, myVpnIp)
		if err != nil {
			return fmt.Errorf("failed to generate key for position %v: %w", i, err)
		}

		p.Cache = append(p.Cache, k)
	}

	return nil
}

// preparePrimaryKey if we are in enforced mode, will do an hkdf extract on the first key to benefit
// outgoing handshake performance, MakeFor does the final expand step
func (p *Psk) preparePrimaryKey(keys []string) error {
	if p.mode != PskEnforced {
		// If we aren't enforcing then there is nothing to prepare
		return nil
	}

	if len(keys) < 1 {
		return ErrNotEnoughPskKeys
	}

	p.key = hkdf.Extract(sha256.New, []byte(keys[0]), nil)
	return nil
}

// sha256KdfFromString generates a full hkdf
func sha256KdfFromString(secret string, vpnIp iputil.VpnIp) ([]byte, error) {
	if len(secret) < MinPskLength {
		return nil, ErrKeyTooShort
	}

	hmacKey := make([]byte, sha256.Size)
	_, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, vpnIp.ToIP()), hmacKey)
	if err != nil {
		return nil, err
	}
	return hmacKey, nil
}
