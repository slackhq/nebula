package nebula

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
	writeLock      sync.Mutex
}

func NewConnectionState(l *logrus.Logger, cs *CertState, crt cert.Certificate, initiator bool, pattern noise.HandshakePattern) (*ConnectionState, error) {
	var dhFunc noise.DHFunc
	switch crt.Curve() {
	case cert.Curve_CURVE25519:
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		if cs.pkcs11Backed {
			dhFunc = noiseutil.DHP256PKCS11
		} else {
			dhFunc = noiseutil.DHP256
		}
	default:
		return nil, fmt.Errorf("invalid curve: %s", crt.Curve())
	}

	var ncs noise.CipherSuite
	if cs.cipher == "chachapoly" {
		ncs = noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256)
	} else {
		ncs = noise.NewCipherSuite(dhFunc, noiseutil.CipherAESGCM, noise.HashSHA256)
	}

	static := noise.DHKey{Private: cs.privateKey, Public: crt.PublicKey()}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   ncs,
		Random:        rand.Reader,
		Pattern:       pattern,
		Initiator:     initiator,
		StaticKeypair: static,
		//NOTE: These should come from CertState (pki.go) when we finally implement it
		PresharedKey:          []byte{},
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("NewConnectionState: %s", err)
	}

	// The queue and ready params prevent a counter race that would happen when
	// sending stored packets and simultaneously accepting new traffic.
	ci := &ConnectionState{
		H:         hs,
		initiator: initiator,
		window:    NewBits(ReplayWindow),
		myCert:    crt,
	}
	// always start the counter from 2, as packet 1 and packet 2 are handshake packets.
	ci.messageCounter.Add(2)

	return ci, nil
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter.Load(),
	})
}

func (cs *ConnectionState) Curve() cert.Curve {
	return cs.myCert.Curve()
}
