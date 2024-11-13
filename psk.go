package nebula

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"golang.org/x/crypto/hkdf"
)

var ErrNotAPskMode = errors.New("not a psk mode")
var ErrKeyTooShort = errors.New("key is too short")
var ErrNotEnoughPskKeys = errors.New("at least 1 key is required")

// MinPskLength is the minimum bytes that we accept for a user defined psk, the choice is arbitrary
const MinPskLength = 8

type PskMode int

const (
	PskAccepting PskMode = 0
	PskSending   PskMode = 1
	PskEnforced  PskMode = 2
)

func NewPskMode(m string) (PskMode, error) {
	switch m {
	case "accepting":
		return PskAccepting, nil
	case "sending":
		return PskSending, nil
	case "enforced":
		return PskEnforced, nil
	}
	return PskAccepting, ErrNotAPskMode
}

func (p PskMode) String() string {
	switch p {
	case PskAccepting:
		return "accepting"
	case PskSending:
		return "sending"
	case PskEnforced:
		return "enforced"
	}

	return "unknown"
}

func (p PskMode) IsValid() bool {
	switch p {
	case PskAccepting, PskSending, PskEnforced:
		return true
	default:
		return false
	}
}

type Psk struct {
	// pskMode sets how psk works, ignored, allowed for incoming, or enforced for all
	mode PskMode

	// primary is the key to use when sending, it may be nil
	primary []byte

	// keys holds all pre-computed psk hkdfs
	// Handshakes iterate this directly
	keys [][]byte
}

// NewPskFromConfig is a helper for initial boot and config reloading.
func NewPskFromConfig(c *config.C) (*Psk, error) {
	sMode := c.GetString("psk.mode", "accepting")
	mode, err := NewPskMode(sMode)
	if err != nil {
		return nil, util.NewContextualError("Could not parse psk.mode", m{"mode": mode}, err)
	}

	return NewPsk(
		mode,
		c.GetStringSlice("psk.keys", nil),
	)
}

// NewPsk creates a new Psk object and handles the caching of all accepted keys
func NewPsk(mode PskMode, keys []string) (*Psk, error) {
	if !mode.IsValid() {
		return nil, ErrNotAPskMode
	}

	psk := &Psk{
		mode: mode,
	}

	err := psk.cachePsks(keys)
	if err != nil {
		return nil, err
	}

	return psk, nil
}

// cachePsks generates all psks we accept and caches them to speed up handshaking
func (p *Psk) cachePsks(keys []string) error {
	if p.mode != PskAccepting && len(keys) < 1 {
		return ErrNotEnoughPskKeys
	}

	p.keys = [][]byte{}

	for i, rk := range keys {
		k, err := sha256KdfFromString(rk)
		if err != nil {
			return fmt.Errorf("failed to generate key for position %v: %w", i, err)
		}

		p.keys = append(p.keys, k)
	}

	if p.mode != PskAccepting {
		// We are either sending or enforcing, the primary key must the first slot
		p.primary = p.keys[0]
	}

	if p.mode != PskEnforced {
		// If we are not enforcing psk use then a nil psk is allowed
		p.keys = append(p.keys, nil)
	}

	return nil
}

// sha256KdfFromString generates a useful key to use from a provided secret
func sha256KdfFromString(secret string) ([]byte, error) {
	if len(secret) < MinPskLength {
		return nil, ErrKeyTooShort
	}

	hmacKey := make([]byte, sha256.Size)
	_, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, nil), hmacKey)
	if err != nil {
		return nil, err
	}

	return hmacKey, nil
}
