package nebula

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
)

const ReplayWindow = 8192

type ConnectionState struct {
	eKey           noiseutil.CipherState
	dKey           noiseutil.CipherState
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
	decryptLock    sync.Mutex
	writeLock      sync.Mutex
}

// newConnectionStateFromResult builds a fully-populated ConnectionState from a
// completed handshake.Result. It seeds messageCounter and the replay window so
// that the post-handshake message indices already used on the wire don't count
// as missed traffic in the data plane.
func newConnectionStateFromResult(r *handshake.Result) *ConnectionState {
	ci := &ConnectionState{
		myCert:    r.MyCert,
		initiator: r.Initiator,
		peerCert:  r.RemoteCert,
		eKey:      noiseutil.NewCipherState(r.EKey, r.Cipher),
		dKey:      noiseutil.NewCipherState(r.DKey, r.Cipher),
		window:    NewBits(ReplayWindow),
	}
	ci.messageCounter.Add(r.MessageIndex)
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	return ci
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

func (cs *ConnectionState) Decrypt(l *slog.Logger, messageCounter uint64, packet []byte, nb []byte) ([]byte, error) {
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return nil, ErrAlreadySeen
	}

	out, err := cs.dKey.DecryptDanger(packet[header.Len:header.Len], packet[:header.Len], packet[header.Len:], messageCounter, nb)
	if err != nil {
		return nil, err
	}

	cs.decryptLock.Lock()
	result = cs.window.Update(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return nil, ErrAlreadySeen
	}
	return out, nil
}

func (cs *ConnectionState) VerifyRelay(l *slog.Logger, messageCounter uint64, packet []byte, nb []byte) error {
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return ErrAlreadySeen
	}

	// The entire body is sent as AD, not encrypted.
	// The packet consists of a 16-byte parsed Nebula header, Associated Data-protected payload, and a trailing 16-byte AEAD signature value.
	// The packet is guaranteed to be at least 16 bytes at this point, b/c it got past the h.Parse() call above. If it's
	// otherwise malformed (meaning, there is no trailing 16 byte AEAD value), then this will result in at worst a 0-length slice
	// which will gracefully fail in the DecryptDanger call.
	signedPayload := packet[:len(packet)-cs.dKey.Overhead()]
	signatureValue := packet[len(packet)-cs.dKey.Overhead():]
	_, err := cs.dKey.DecryptDanger(nil, signedPayload, signatureValue, messageCounter, nb)
	if err != nil {
		return err
	}

	cs.decryptLock.Lock()
	result = cs.window.Update(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return ErrAlreadySeen
	}
	return nil
}
