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
