package nebula

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
)

const (
	ReplayWindow = 8192

	// RehandshakeAfterMessages rolls keys inside the AES-GCM data-volume margin (~2^-36 advantage at 64KB frames).
	RehandshakeAfterMessages = uint64(1) << 34

	// RejectAfterMessages is the nonce ceiling enforced by noiseutil; a tunnel here is deleted locally, not notified.
	RejectAfterMessages = noiseutil.RejectAfterMessages
)

// RehandshakeAfterMessages must stay below RejectAfterMessages so tunnels roll before the hard send stop.
const _ = RejectAfterMessages - RehandshakeAfterMessages

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
func newConnectionStateFromResult(r *handshake.Result) (*ConnectionState, error) {
	// Refuse a MessageIndex too big for the replay window: it can only be a bug, and would spin the seed loop below.
	if r.MessageIndex >= ReplayWindow {
		return nil, fmt.Errorf("handshake message index %d exceeds replay window", r.MessageIndex)
	}

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
	return ci, nil
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter.Load(),
	})
}

// NextMessageCounter reserves the next 1-based counter; RejectAfterMessages is the first we refuse, pinned to not wrap.
func (cs *ConnectionState) NextMessageCounter() (uint64, bool) {
	c := cs.messageCounter.Add(1)
	if c >= RejectAfterMessages {
		cs.messageCounter.Store(RejectAfterMessages)
		return c, false
	}
	return c, true
}

func (cs *ConnectionState) Curve() cert.Curve {
	return cs.myCert.Curve()
}

func (cs *ConnectionState) Decrypt(l *slog.Logger, messageCounter uint64, out []byte, packet []byte, nb []byte) ([]byte, error) {
	var err error
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return nil, ErrAlreadySeen
	}

	out, err = cs.dKey.DecryptDanger(out, packet[:header.Len], packet[header.Len:], messageCounter, nb)
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

// VerifyRelay verifies AEAD protected (but not encrypted) relay frames. packet must be length-checked by the caller.
func (cs *ConnectionState) VerifyRelay(l *slog.Logger, messageCounter uint64, packet []byte, nb []byte) error {
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return ErrAlreadySeen
	}

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
