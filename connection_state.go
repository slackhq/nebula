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

// sessionEpoch hands out a receiver-local ordinal to every ConnectionState at creation. The RX
// staging sort (overlay/batch) orders packets by (epoch, message counter). A re-handshake never
// rekeys an existing tunnel; it brings up a new hostinfo and ConnectionState with a counter space
// starting near zero, while the old tunnel keeps decrypting until torn down. During that cutover
// one flush batch can hold packets from both tunnels, and the epoch keeps the old tunnel's
// packets sorted first.
var sessionEpoch atomic.Uint64

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
	// queueKeys, when set, holds one send cipher per routine for a cipher that needs writeLock, see encrypter
	queueKeys []queueKey
	// epoch is this session's sessionEpoch ordinal. Immutable after creation.
	epoch uint64
}

// newConnectionStateFromResult builds a fully-populated ConnectionState from a
// completed handshake.Result. It seeds messageCounter and the replay window so
// that the post-handshake message indices already used on the wire don't count
// as missed traffic in the data plane. window is the replay window length, a power of two of at least ReplayWindow.
// encryptQueues above 1 gives the tunnel one send cipher per routine when noiseutil.EncryptLockNeeded, see encrypter.
func newConnectionStateFromResult(r *handshake.Result, window uint64, encryptQueues int) (*ConnectionState, error) {
	if window < ReplayWindow || window&(window-1) != 0 {
		return nil, fmt.Errorf("replay window %d must be a power of two of at least %d", window, ReplayWindow)
	}

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
		window:    NewBits(window),
		epoch:     sessionEpoch.Add(1),
	}
	if encryptQueues > 1 && noiseutil.EncryptLockNeeded {
		ci.queueKeys = newQueueKeys(r, encryptQueues)
	}
	ci.messageCounter.Add(r.MessageIndex)
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	return ci, nil
}

// queueKey is one of a tunnel's per routine send ciphers and the lock serializing its encryptions
type queueKey struct {
	mu  sync.Mutex
	key noiseutil.CipherState
	// Keep each routine's lock on its own cache line
	_ [64 - 8 - 16]byte
}

// newQueueKeys builds n send ciphers from the tunnel's send key, nil if the cipher can't be built that way.
//
// A cipher that needs writeLock (FIPS 140, boringcrypto) refuses a nonce that is not strictly increasing. Every
// routine reserves its counters from the shared messageCounter under its own cipher's lock, so the counters each
// cipher sees still strictly increase, and every counter is used once across all of them.
func newQueueKeys(r *handshake.Result, n int) []queueKey {
	k := r.EKey.UnsafeKey()
	keys := make([]queueKey, n)
	for i := range keys {
		cs, ok := r.Cipher.Cipher(k).(noiseutil.CipherState)
		if !ok {
			return nil
		}
		keys[i].key = cs
	}
	return keys
}

// encrypter returns the cipher queue q sends with and the lock to hold around reserving a counter and encrypting
// when noiseutil.EncryptLockNeeded. That is queue q's own cipher when the tunnel has per routine ciphers, otherwise
// the tunnel's one cipher and writeLock.
func (cs *ConnectionState) encrypter(q int) (noiseutil.CipherState, *sync.Mutex) {
	if n := len(cs.queueKeys); n > 0 {
		k := &cs.queueKeys[q%n]
		return k.key, &k.mu
	}
	return cs.eKey, &cs.writeLock
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
