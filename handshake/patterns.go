package handshake

import (
	"fmt"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/header"
)

// msgFlags tracks what application data a handshake message carries.
type msgFlags struct {
	expectsPayload bool // message carries indexes and time
	expectsCert    bool // message carries the certificate
}

// subtypeInfo bundles the noise pattern with the per-message flags for a
// given handshake subtype.
//
// presharedKeyPlacement maps directly onto noise.Config.PresharedKeyPlacement.
// 0 means no PSK (the legacy IXPSK0 subtype is misnamed — flynn/noise only
// activates a PSK when the byte slice is non-empty, so subtype 0 with an
// empty PSK behaves as plain IX). A non-zero placement turns the subtype
// into a real Noise psk pattern; the PSK material itself is supplied
// elsewhere (Credential.pqPSKLookup or noise.Config.PresharedKey).
type subtypeInfo struct {
	pattern               noise.HandshakePattern
	msgs                  []msgFlags
	presharedKeyPlacement int
}

// subtypeInfos defines the noise pattern and message content layout for each
// handshake subtype.
var subtypeInfos = map[header.MessageSubType]subtypeInfo{
	// IX: 2 messages, both carry payload and cert.
	// PSK at placement 0 only takes effect if non-empty bytes are supplied;
	// historically this subtype carried no PSK at all.
	header.HandshakeIXPSK0: {
		pattern: noise.HandshakeIX,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
		presharedKeyPlacement: 0,
	},

	// IXpsk2: same wire shape as IX, but the PSK token is appended to msg2
	// so the responder can identify the peer from msg1's static key before
	// committing to a PSK. This enables per-peer PSK without out-of-band
	// peer-identity prediction at handshake start.
	header.HandshakeIXPSK2: {
		pattern: noise.HandshakeIX,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
		presharedKeyPlacement: 2,
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
