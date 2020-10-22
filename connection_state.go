package nebula

import (
	"crypto/rand"
	"encoding/json"
	"sync"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
)

const ReplayWindow = 1024

type ConnectionState struct {
	eKey           *NebulaCipherState
	dKey           *NebulaCipherState
	H              *noise.HandshakeState
	certState      *CertState
	peerCert       *cert.NebulaCertificate
	initiator      bool
	messageCounter *uint64
	window         *Bits
	queueLock      sync.Mutex
	// writeLock      sync.Mutex
	ready bool
}

func (f *Interface) newConnectionState(initiator bool, pattern noise.HandshakePattern, psk []byte, pskStage int) *ConnectionState {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	if f.cipher == "chachapoly" {
		cs = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	}

	curCertState := f.certState
	static := noise.DHKey{Private: curCertState.privateKey, Public: curCertState.publicKey}

	b := NewBits(ReplayWindow)
	// Clear out bit 0, we never transmit it and we don't want it showing as packet loss
	b.Update(0)

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Random:                rand.Reader,
		Pattern:               pattern,
		Initiator:             initiator,
		StaticKeypair:         static,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskStage,
	})
	if err != nil {
		return nil
	}

	// The queue and ready params prevent a counter race that would happen when
	// sending stored packets and simultaneously accepting new traffic.
	ci := &ConnectionState{
		H:              hs,
		initiator:      initiator,
		window:         b,
		ready:          false,
		certState:      curCertState,
		messageCounter: new(uint64),
	}

	return ci
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter,
		"ready":           cs.ready,
	})
}
