package nebula

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
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
	// epoch is this session's sessionEpoch ordinal. Immutable after creation.
	epoch uint64
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
		epoch:     sessionEpoch.Add(1),
	}
	ci.messageCounter.Add(r.MessageIndex)
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	return ci, nil
}

// newLaneConnectionState derives multiport lane s's session from the base
// tunnel's material. Each key is an HKDF expansion of the base tunnel's matching
// key, labelled with the lane index, so the pair stays matched with no extra
// negotiation: Noise leaves our send key equal to the peer's receive key, and
// expanding both with the same label preserves that.
//
// The lane gets its own counter and replay window starting from zero. No
// handshake messages were spent on it, so unlike the base session there is
// nothing to seed.
func newLaneConnectionState(m *laneMaterial, lane uint8) (*ConnectionState, error) {
	if lane == 0 {
		return nil, fmt.Errorf("lane 0 is the base session")
	}

	eKey, err := deriveLaneKey(m.eKey, lane)
	if err != nil {
		return nil, err
	}
	dKey, err := deriveLaneKey(m.dKey, lane)
	if err != nil {
		return nil, err
	}

	return &ConnectionState{
		myCert:    m.myCert,
		initiator: m.initiator,
		peerCert:  m.peerCert,
		eKey:      noiseutil.NewCipherStateFromKey(eKey, m.cipher),
		dKey:      noiseutil.NewCipherStateFromKey(dKey, m.cipher),
		window:    NewBits(ReplayWindow),
		epoch:     sessionEpoch.Add(1),
	}, nil
}

// deriveLaneKey expands a base tunnel key into the key for one lane.
func deriveLaneKey(base [32]byte, lane uint8) ([32]byte, error) {
	var out [32]byte
	// The base key is already unique to this tunnel and direction, so the lane
	// index is the only thing that needs to vary; no salt is required.
	k, err := hkdf.Key(sha256.New, base[:], nil, laneKeyInfo+" "+strconv.Itoa(int(lane)), len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], k)
	return out, nil
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
