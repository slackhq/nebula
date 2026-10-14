package handshake

import (
	"fmt"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/header"
)

// msgFlags tracks what application data a handshake message carries.
type msgFlags struct {
	expectsPayload bool // message carries indexes and time
	expectsCert    bool // message carries the certificate
	kemKey         bool // payload carries an ML-KEM encapsulation key
	kemCiphertext  bool // message is prefixed with the ML-KEM ciphertext for the peer's key
}

// subtypeInfo bundles the noise pattern with the per-message flags for a
// given handshake subtype.
type subtypeInfo struct {
	pattern      noise.HandshakePattern
	pskPlacement int // noise psk modifier position, 0 means no psk token
	msgs         []msgFlags

	// hybrid patterns carry composite static keys and need version 3
	// certificates on both sides; every other pattern refuses them.
	hybrid bool
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

	// IX with an ephemeral ML-KEM-1024 exchange:
	//   msg1 (I->R): payload + cert + encapsulation key
	//   msg2 (R->I): ciphertext || noise(payload + cert)
	// The responder encapsulates after reading msg1 and mixes the shared secret in
	// through the psk2 token at the end of msg2. The ciphertext travels outside the
	// noise message because the initiator needs the secret before it can process
	// that token.
	header.HandshakeIXPSK2MLKEM1024: {
		pattern:      noise.HandshakeIX,
		pskPlacement: 2,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true, kemKey: true},
			{expectsPayload: true, expectsCert: true, kemCiphertext: true},
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
		hybrid:  true,
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

func subtypeInfoFor(subtype header.MessageSubType) (subtypeInfo, error) {
	if info, ok := subtypeInfos[subtype]; ok {
		return info, nil
	}
	return subtypeInfo{}, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}
