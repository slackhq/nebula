package nebula

import (
	"crypto/rand"
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/noiseutil"
)

const ReplayWindow = 1024

type ConnectionState struct {
	eKey           *NebulaCipherState
	dKey           *NebulaCipherState
	H              *noise.HandshakeState
	certState      *CertState
	peerCert       *cert.NebulaCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
	queueLock      sync.Mutex
	writeLock      sync.Mutex
	ready          bool
}

func (f *Interface) newConnectionState(l *logrus.Logger, initiator bool, pattern noise.HandshakePattern, psk []byte, pskStage int) *ConnectionState {
	var dhFunc noise.DHFunc
	curCertState := f.certState.Load()

	switch curCertState.certificate.Details.Curve {
	case cert.Curve_CURVE25519:
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		dhFunc = noiseutil.DHP256
	default:
		l.Errorf("invalid curve: %s", curCertState.certificate.Details.Curve)
		return nil
	}
	cs := noise.NewCipherSuite(dhFunc, noise.CipherAESGCM, noise.HashSHA256)
	if f.cipher == "chachapoly" {
		cs = noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256)
	}

	static := noise.DHKey{Private: curCertState.privateKey, Public: curCertState.publicKey}

	b := NewBits(ReplayWindow)
	// Clear out bit 0, we never transmit it and we don't want it showing as packet loss
	b.Update(l, 0)

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
		H:         hs,
		initiator: initiator,
		window:    b,
		ready:     false,
		certState: curCertState,
	}

	return ci
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter.Load(),
		"ready":           cs.ready,
	})
}
