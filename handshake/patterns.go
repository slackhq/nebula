package handshake

import (
	"fmt"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// msgFlags tracks what application data a handshake message carries.
type msgFlags struct {
	expectsPayload bool // message carries indexes and time
	expectsCert    bool // message carries the certificate
}

// subtypeInfo bundles the noise pattern with the per-message flags for a
// given handshake subtype.
type subtypeInfo struct {
	pattern noise.HandshakePattern
	msgs    []msgFlags

	// kem is the KEM of a post-quantum pattern, hybrid or KEM-only, nil for
	// any other.
	kem noise.KEMFunc

	// curve reports whether certificates on a curve go with this pattern. Each
	// post-quantum pattern takes its own curve, and the classical one the
	// classical curves; a handshake never mixes them.
	curve func(cert.Curve) bool
}

func onClassicalCurve(c cert.Curve) bool { return !cert.IsPostQuantum(c) }
func onHybridCurve(c cert.Curve) bool    { return c == cert.Curve_P384_MLKEM1024_MLDSA87 }
func onPureCurve(c cert.Curve) bool      { return c == cert.Curve_MLKEM1024_MLDSA87 }

// subtypeInfos defines the noise pattern and message content layout for each
// handshake subtype.
var subtypeInfos = map[header.MessageSubType]subtypeInfo{
	// IX: 2 messages, both carry payload and cert
	header.HandshakeIXPSK0: {
		pattern: noise.HandshakeIX,
		curve:   onClassicalCurve,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
	},

	// Hybrid IX (github.com/DefinedNet/noise, see its PQ_RESEARCH.md):
	//   msg1 (I->R): e, s                          payload + cert
	//   msg2 (R->I): ekem, skem, e, ee, se, s, es  payload + cert
	//   msg3 (I->R): skem
	// e and s are composite, P-384 || ML-KEM-1024, except the responder's e: it
	// follows the responder's ekem, which already completed the ephemeral KEM
	// exchange, so it carries only the P-384 key. The static key is the hybrid
	// certificate's public key, so it travels in s and the certificate leaves it
	// out, as for any curve. The responder authenticates the initiator when msg3
	// decrypts, and the initiator the responder when the first packet under the
	// new keys does.
	header.HandshakeIXHybrid: {
		pattern: noise.HandshakeHybridIX,
		kem:     KEMMLKEM1024,
		curve:   onHybridCurve,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
			{},
		},
	},

	// pqIX of PQNoise (eprint.iacr.org/2022/539), ML-KEM-1024 alone:
	//   msg1 (I->R): e, s              payload + cert
	//   msg2 (R->I): ekem, skem, s     payload + cert
	//   msg3 (I->R): skem
	// e and s are ML-KEM-1024 encapsulation keys, s the certificate's public
	// key, and every secret comes from a KEM. Authentication works as in the
	// hybrid pattern: the responder's when msg3 decrypts, the initiator's when
	// the first packet under the new keys does.
	header.HandshakeIXPQ: {
		pattern: noise.HandshakePQIX,
		kem:     KEMMLKEM1024,
		curve:   onPureCurve,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
			{},
		},
	},

	// XX: 3 messages
	//   msg1 (I->R): payload only
	//   msg2 (R->I): payload + cert
	//   msg3 (I->R): cert only
	//header.HandshakeXXPSK0: {
	//	pattern: noise.HandshakeXX,
	//	msgs: []msgFlags{
	//		{expectsPayload: true, expectsCert: false},
	//		{expectsPayload: true, expectsCert: true},
	//		{expectsPayload: false, expectsCert: true},
	//	},
	//},
}

// IsPostQuantum reports whether subtype is a post-quantum handshake, hybrid or
// KEM-only: three messages, too big for one packet, and certificates on that
// pattern's post-quantum curve.
func IsPostQuantum(subtype header.MessageSubType) bool {
	return subtypeInfos[subtype].kem != nil
}

func subtypeInfoFor(subtype header.MessageSubType) (subtypeInfo, error) {
	if info, ok := subtypeInfos[subtype]; ok {
		return info, nil
	}
	return subtypeInfo{}, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}
