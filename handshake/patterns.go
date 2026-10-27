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

	// kem is the KEM of a hybrid pattern, nil for any other. Hybrid patterns
	// carry composite static keys and need version 3 certificates on both
	// sides, in suites using this KEM; every other pattern refuses them.
	kem noise.KEMFunc
}

// subtypeInfos defines the noise pattern and message content layout for each
// handshake subtype.
var subtypeInfos = map[header.MessageSubType]subtypeInfo{
	// IX: 2 messages, both carry payload and cert
	header.HandshakeIXPSK0: {
		pattern: noise.HandshakeIX,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
	},

	// Hybrid IX (github.com/DefinedNet/noise, see its PQ_RESEARCH.md):
	//   msg1 (I->R): e, s                          payload + cert
	//   msg2 (R->I): ekem, skem, e, ee, se, s, es  payload + cert
	//   msg3 (I->R): skem
	// e and s are composite, classical || ML-KEM-1024, except the responder's e:
	// it follows the responder's ekem, which already completed the ephemeral KEM
	// exchange, so it carries only the classical key. The static ML-KEM key is
	// the post-quantum half of the v3 certificate's public key, so it travels in
	// s and the certificate leaves it out. The responder authenticates the
	// initiator when msg3 decrypts, and the initiator the responder when the
	// first packet under the new keys does.
	header.HandshakeIXHybridMLKEM1024: {
		pattern: noise.HandshakeHybridIX,
		kem:     KEMMLKEM1024,
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

// hybridSubtypes maps the suite of a version 3 certificate to the hybrid
// subtype for its KEM. Peers need the same KEM, not the same suite, so suites
// sharing a KEM share a subtype; the suite itself travels in the certificate.
var hybridSubtypes = map[cert.PQSuite]header.MessageSubType{
	cert.PQSuite_MLKEM1024_MLDSA87: header.HandshakeIXHybridMLKEM1024,
}

// HybridSubtype returns the hybrid handshake subtype for the KEM of a version 3
// certificate's suite.
func HybridSubtype(suite cert.PQSuite) (header.MessageSubType, bool) {
	st, ok := hybridSubtypes[suite]
	return st, ok
}

// IsHybrid reports whether subtype, fragmented or not, is a hybrid handshake, one that needs version
// 3 certificates.
func IsHybrid(subtype header.MessageSubType) bool {
	if pattern, ok := header.FragmentedPattern(subtype); ok {
		subtype = pattern
	}
	return subtypeInfos[subtype].kem != nil
}

func subtypeInfoFor(subtype header.MessageSubType) (subtypeInfo, error) {
	if info, ok := subtypeInfos[subtype]; ok {
		return info, nil
	}
	return subtypeInfo{}, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}
