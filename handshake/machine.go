package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

var (
	ErrInitiateOnResponder   = errors.New("Initiate called on responder")
	ErrInitiateAlreadyCalled = errors.New("Initiate already called")
	ErrInitiateNotCalled     = errors.New("Initiate must be called before ProcessPacket for initiators")
	ErrPacketTooShort        = errors.New("packet too short")
	ErrPublicKeyMismatch     = errors.New("public key mismatch between certificate and handshake")
	ErrIncompleteHandshake   = errors.New("handshake completed without receiving required content")
	ErrMachineFailed         = errors.New("handshake machine has failed")
	ErrUnknownSubtype        = errors.New("unknown handshake subtype")
	ErrMissingContent        = errors.New("expected handshake content but message was empty")
	ErrUnexpectedContent     = errors.New("received unexpected handshake content")
	ErrIndexAllocation       = errors.New("failed to allocate local index")
)

// HandshakeCredential holds everything needed to participate in a handshake
// at a given cert version.
type HandshakeCredential struct {
	Cert        cert.Certificate  // the certificate
	Bytes       []byte            // pre-marshaled certificate bytes
	Version     cert.Version      // certificate version
	Curve       cert.Curve        // certificate curve
	staticKey   noise.DHKey       // private + public keypair
	cipherSuite noise.CipherSuite // pre-built cipher suite (DH + cipher + hash)
}

// NewHandshakeCredential creates a HandshakeCredential with all material needed
// for handshake participation. The cipherSuite should be pre-built by the caller
// with the appropriate DH function, cipher, and hash.
func NewHandshakeCredential(
	c cert.Certificate,
	hsBytes []byte,
	privateKey []byte,
	cipherSuite noise.CipherSuite,
) *HandshakeCredential {
	return &HandshakeCredential{
		Cert:        c,
		Bytes:       hsBytes,
		Version:     c.Version(),
		Curve:       c.Curve(),
		staticKey:   noise.DHKey{Private: privateKey, Public: c.PublicKey()},
		cipherSuite: cipherSuite,
	}
}

// NewHandshakeState creates a noise.HandshakeState from this credential.
func (hc *HandshakeCredential) NewHandshakeState(initiator bool, pattern noise.HandshakePattern) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           hc.cipherSuite,
		Random:                rand.Reader,
		Pattern:               pattern,
		Initiator:             initiator,
		StaticKeypair:         hc.staticKey,
		PresharedKey:          []byte{},
		PresharedKeyPlacement: 0,
	})
}

// GetCredentialFunc returns the handshake credential for the given version,
// or nil if that version is not available.
type GetCredentialFunc func(v cert.Version) *HandshakeCredential

// IndexAllocator is called by the Machine to allocate a local index for the
// handshake. It is called at most once, when the first outgoing message that
// carries a payload is built.
type IndexAllocator func() (uint32, error)

// CertVerifier is called by the Machine after reconstructing the peer's
// certificate from the handshake. The verifier performs all validation
// (CA trust, expiry, policy checks, allow lists) and returns a caller-defined
// result type T.
type CertVerifier[T any] func(cert.Certificate) (T, error)

// CompletedHandshake contains the results of a successful handshake.
// Returned by ProcessPacket when the handshake is complete.
type CompletedHandshake[T any] struct {
	EKey          *noise.CipherState
	DKey          *noise.CipherState
	MyCert        cert.Certificate
	RemoteCert    T
	RemoteIndex   uint32
	LocalIndex    uint32
	HandshakeTime uint64
	MessageIndex  uint64 // number of messages exchanged during the handshake
	Initiator     bool
}

// msgFlags tracks what application data a handshake message carries.
type msgFlags struct {
	expectsPayload bool // message carries indexes and time
	expectsCert    bool // message carries the certificate
}

// subtypeMsgFlags defines what content each message carries for a given handshake subtype.
// This map is read during NewMachine; it is not safe for concurrent writes.
var subtypeMsgFlags = map[header.MessageSubType][]msgFlags{
	// IX: 2 messages, both carry payload and cert
	header.HandshakeIXPSK0: {
		{expectsPayload: true, expectsCert: true},
		{expectsPayload: true, expectsCert: true},
	},

	// XX: 3 messages
	//   msg1 (I->R): payload only
	//   msg2 (R->I): payload + cert
	//   msg3 (I->R): cert only
	//header.HandshakeXXPSK0: {
	//	{expectsPayload: true, expectsCert: false},
	//	{expectsPayload: true, expectsCert: true},
	//	{expectsPayload: false, expectsCert: true},
	//},
}

func messageFlags(subtype header.MessageSubType) ([]msgFlags, error) {
	if flags, ok := subtypeMsgFlags[subtype]; ok {
		return flags, nil
	}
	return nil, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}

// Machine drives a Noise handshake through N messages. It handles Noise
// protocol operations, certificate reconstruction, and payload encoding.
// Certificate validation is delegated to the caller via CertVerifier[T].
//
// T is the caller-defined type returned by the cert verifier. For nebula
// this is *cert.CachedCertificate. For other consumers it can be any type.
//
// A Machine is not safe for concurrent use. The caller must ensure that
// Initiate and ProcessPacket are not called concurrently.
type Machine[T any] struct {
	hs             *noise.HandshakeState
	getCred        GetCredentialFunc
	allocIndex     IndexAllocator
	verifier       CertVerifier[T]
	result         *CompletedHandshake[T]
	msgs           []msgFlags
	myVersion      cert.Version
	subtype        header.MessageSubType
	indexAllocated bool
	remoteCertSet  bool
	payloadSet     bool
	failed         bool
}

// NewMachine creates a handshake state machine. The caller provides a
// pre-built noise.HandshakeState (owning cipher suite and key selection),
// the subtype (which determines message content layout), and an
// IndexAllocator that will be called lazily when the first outgoing
// payload is built.
func NewMachine[T any](
	hs *noise.HandshakeState,
	version cert.Version,
	getCred GetCredentialFunc,
	verifier CertVerifier[T],
	allocIndex IndexAllocator,
	initiator bool,
	subtype header.MessageSubType,
) (*Machine[T], error) {
	msgs, err := messageFlags(subtype)
	if err != nil {
		return nil, err
	}

	return &Machine[T]{
		hs:         hs,
		subtype:    subtype,
		msgs:       msgs,
		getCred:    getCred,
		allocIndex: allocIndex,
		verifier:   verifier,
		myVersion:  version,
		result: &CompletedHandshake[T]{
			Initiator: initiator,
		},
	}, nil
}

// Failed returns true if the Machine is in an unrecoverable state.
func (m *Machine[T]) Failed() bool {
	return m.failed
}

// requireComplete checks that both a peer cert and payload have been received.
// Marks the machine as failed if not.
func (m *Machine[T]) requireComplete() error {
	if !m.payloadSet || !m.remoteCertSet {
		m.failed = true
		return ErrIncompleteHandshake
	}
	return nil
}

// myMsgFlags returns the flags for the current outgoing message.
func (m *Machine[T]) myMsgFlags() msgFlags {
	idx := m.hs.MessageIndex()
	if idx < len(m.msgs) {
		return m.msgs[idx]
	}
	return msgFlags{}
}

// peerMsgFlags returns the flags for the message we just read.
func (m *Machine[T]) peerMsgFlags() msgFlags {
	idx := m.hs.MessageIndex() - 1
	if idx >= 0 && idx < len(m.msgs) {
		return m.msgs[idx]
	}
	return msgFlags{}
}

// Initiate produces the first handshake message. Only valid for initiators,
// and must be called exactly once before ProcessPacket.
// An error return may not indicate a fatal condition, check Failed() to
// determine if the Machine can still be used.
func (m *Machine[T]) Initiate(out []byte) ([]byte, error) {
	if m.failed {
		return nil, ErrMachineFailed
	}
	if !m.result.Initiator {
		m.failed = true
		return nil, ErrInitiateOnResponder
	}
	if m.hs.MessageIndex() != 0 {
		m.failed = true
		return nil, ErrInitiateAlreadyCalled
	}

	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		m.failed = true
		return nil, err
	}

	start := len(out)
	out = append(out[:start], make([]byte, header.Len)...)
	header.Encode(out[start:], header.Version, header.Handshake, m.subtype, 0, 1)

	out, _, _, err = m.hs.WriteMessage(out, hsBytes)
	if err != nil {
		m.failed = true
		return nil, fmt.Errorf("noise WriteMessage: %w", err)
	}

	return out, nil
}

// ProcessPacket handles an incoming handshake message. It advances the Noise
// state, validates the peer certificate via the verifier, and optionally
// produces a response appended to out (which may be nil).
// Returns a non-nil CompletedHandshake when the handshake is complete.
// An error return may not indicate a fatal condition, check Failed() to
// determine if the Machine can still be used.
func (m *Machine[T]) ProcessPacket(out, packet []byte) ([]byte, *CompletedHandshake[T], error) {
	if m.failed {
		return nil, nil, ErrMachineFailed
	}
	if len(packet) < header.Len {
		return nil, nil, ErrPacketTooShort
	}
	if m.result.Initiator && m.hs.MessageIndex() == 0 {
		m.failed = true
		return nil, nil, ErrInitiateNotCalled
	}

	msg, eKey, dKey, err := m.hs.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		// Noise ReadMessage failed. The noise library checkpoints and rolls back
		// on failure, so the Machine is still alive. The caller can retry with
		// a different packet.
		return nil, nil, fmt.Errorf("noise ReadMessage: %w", err)
	}

	// From here on, noise state has advanced. Any error is fatal.
	flags := m.peerMsgFlags()

	if err := m.processPayload(msg, flags); err != nil {
		return nil, nil, err
	}

	// If ReadMessage derived keys, the handshake is complete
	if eKey != nil {
		if err := m.requireComplete(); err != nil {
			return nil, nil, err
		}
		return nil, m.completed(eKey, dKey), nil
	}

	// ReadMessage didn't complete, produce the next outgoing message
	out, dk, ek, err := m.buildResponse(out)
	if err != nil {
		m.failed = true
		return nil, nil, err
	}

	if ek != nil {
		if err := m.requireComplete(); err != nil {
			return nil, nil, err
		}
		return out, m.completed(ek, dk), nil
	}

	return out, nil, nil
}

func (m *Machine[T]) completed(eKey, dKey *noise.CipherState) *CompletedHandshake[T] {
	m.result.EKey = eKey
	m.result.DKey = dKey
	m.result.MessageIndex = uint64(m.hs.MessageIndex())
	return m.result
}

func (m *Machine[T]) processPayload(msg []byte, flags msgFlags) error {
	if len(msg) == 0 {
		if flags.expectsPayload || flags.expectsCert {
			m.failed = true
			return ErrMissingContent
		}
		return nil
	}

	payload, err := UnmarshalPayload(msg)
	if err != nil {
		m.failed = true
		return fmt.Errorf("unmarshal handshake: %w", err)
	}

	// Assert the payload contains exactly what we expect
	hasPayloadData := payload.InitiatorIndex != 0 || payload.ResponderIndex != 0 || payload.Time != 0
	if hasPayloadData != flags.expectsPayload {
		m.failed = true
		return ErrUnexpectedContent
	}

	hasCertData := len(payload.Cert) > 0
	if hasCertData != flags.expectsCert {
		m.failed = true
		return ErrUnexpectedContent
	}

	// Process payload
	if flags.expectsPayload {
		if m.result.Initiator {
			m.result.RemoteIndex = payload.ResponderIndex
		} else {
			m.result.RemoteIndex = payload.InitiatorIndex
		}
		m.result.HandshakeTime = payload.Time
		m.payloadSet = true
	}

	// Process certificate
	if flags.expectsCert {
		if err := m.validateCert(payload); err != nil {
			return err
		}
	}

	return nil
}

func (m *Machine[T]) validateCert(payload Payload) error {
	rc, err := cert.Recombine(
		cert.Version(payload.CertVersion),
		payload.Cert,
		m.hs.PeerStatic(),
		m.getCred(m.myVersion).Curve,
	)
	if err != nil {
		m.failed = true
		return fmt.Errorf("recombine cert: %w", err)
	}

	if !bytes.Equal(rc.PublicKey(), m.hs.PeerStatic()) {
		m.failed = true
		return ErrPublicKeyMismatch
	}

	// Version negotiation, if the peer sent a different version and we have it, switch
	if rc.Version() != m.myVersion {
		if m.getCred(rc.Version()) != nil {
			m.myVersion = rc.Version()
		}
	}

	verified, err := m.verifier(rc)
	if err != nil {
		m.failed = true
		return fmt.Errorf("verify cert: %w", err)
	}

	m.result.RemoteCert = verified
	m.remoteCertSet = true
	return nil
}

func (m *Machine[T]) marshalOutgoing(flags msgFlags) ([]byte, error) {
	if !flags.expectsPayload && !flags.expectsCert {
		return nil, nil
	}

	var p Payload
	if flags.expectsPayload {
		if !m.indexAllocated {
			index, err := m.allocIndex()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrIndexAllocation, err)
			}
			m.result.LocalIndex = index
			m.indexAllocated = true
		}

		if m.result.Initiator {
			p.InitiatorIndex = m.result.LocalIndex
		} else {
			p.ResponderIndex = m.result.LocalIndex
			p.InitiatorIndex = m.result.RemoteIndex
		}
		p.Time = uint64(time.Now().UnixNano())
	}
	if flags.expectsCert {
		cred := m.getCred(m.myVersion)
		p.Cert = cred.Bytes
		p.CertVersion = uint32(cred.Version)
		m.result.MyCert = cred.Cert
	}

	return MarshalPayload(nil, p), nil
}

func (m *Machine[T]) buildResponse(out []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, nil, nil, err
	}

	start := len(out)
	out = append(out[:start], make([]byte, header.Len)...)
	header.Encode(
		out[start:],
		header.Version, header.Handshake, m.subtype,
		m.result.RemoteIndex,
		uint64(m.hs.MessageIndex()+1),
	)

	out, dKey, eKey, err := m.hs.WriteMessage(out, hsBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("noise WriteMessage: %w", err)
	}

	return out, dKey, eKey, nil
}
