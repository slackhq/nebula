package handshake

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// IndexAllocator is called by the Machine to allocate a local index for the
// handshake. It is called at most once, when the first outgoing message that
// carries a payload is built.
//
// Implementations MUST NOT return 0. Zero is reserved as a sentinel meaning
// "no index assigned" on the wire and in the payload-presence checks. If an
// allocator ever returned 0, a legitimate handshake's payload could be
// indistinguishable from an empty one and would be rejected.
type IndexAllocator func() (uint32, error)

// CertVerifier is called by the Machine after reconstructing the peer's
// certificate from the handshake. The verifier performs all validation
// (CA trust, expiry, policy checks, allow lists).
type CertVerifier func(cert.Certificate) (*cert.CachedCertificate, error)

// Result contains the results of a successful handshake.
// Returned by ProcessPacket when the handshake is complete.
type Result struct {
	EKey          *noise.CipherState
	DKey          *noise.CipherState
	Cipher        noise.CipherFunc // identifies which post-handshake CipherState the data plane should wrap EKey/DKey in
	MyCert        cert.Certificate
	RemoteCert    *cert.CachedCertificate
	RemoteIndex   uint32
	LocalIndex    uint32
	HandshakeTime uint64
	MessageIndex  uint64 // number of messages exchanged during the handshake
	Initiator     bool
	Subtype       header.MessageSubType // IXPSK0 or IXPSK2; lets ConnectionState know whether a PQ PSK was mixed in
}

// Machine drives a Noise handshake through N messages. It handles Noise
// protocol operations, certificate reconstruction, and payload encoding.
// Certificate validation is delegated to the caller via CertVerifier.
//
// A Machine is not safe for concurrent use. The caller must ensure that
// Initiate and ProcessPacket are not called concurrently.
//
// Error contract: when ProcessPacket or Initiate returns an error, callers
// must check Failed() to decide what to do next. If Failed() is false the
// underlying noise state was not advanced (the packet was rejected before
// ReadMessage took effect, or the rejection is non-fatal like a stale
// retransmit) and the Machine can accept another packet. If Failed() is
// true the Machine is unrecoverable and the caller must abandon it.
type Machine struct {
	hs             *noise.HandshakeState
	cred           *Credential // bound credential, kept for PSK lookup on responder side
	getCred        GetCredentialFunc
	allocIndex     IndexAllocator
	verifier       CertVerifier
	result         *Result
	msgs           []msgFlags
	myVersion      cert.Version
	subtype        header.MessageSubType
	pskPlacement   int
	pskInjected    bool // responder: true once SetPresharedKey has been called for psk2
	indexAllocated bool
	remoteCertSet  bool
	payloadSet     bool
	failed         bool
	// pskChooser, when set on a responder at psk placement 2, is
	// consulted at inject time with the initiator's static key; a true
	// return makes injectResponderPSK prefer the previous-epoch PSK
	// (falling back to current when no previous exists). Set by the
	// handshake manager from its epoch-skew hint cache.
	pskChooser func(peerStaticPubKey []byte) bool
	// usedPrevPSK records that the responder injected the previous-
	// epoch PSK (epoch-skew healing path).
	usedPrevPSK bool
	// pskSwapped marks that SwapPSK has been used; one swap per machine.
	pskSwapped bool
}

// NewMachine creates a handshake state machine. The subtype determines both
// the noise pattern and the per-message content layout. The credential for
// `version` is fetched via getCred and used to seed the noise.HandshakeState.
// IndexAllocator is called lazily when the first outgoing payload is built.
//
// peerStaticPubKey is required when the subtype's PSK placement is >= 2 and
// this Machine is an initiator: the PSK is preset in the noise config so it
// can be mixed when the initiator processes msg2. Responders pass nil; they
// learn the peer's static from msg1 and mix the PSK before producing msg2.
//
// peerCert is the cached peer certificate for the initiator at PSK
// placement 2, used by the underlying PSKLookupFunc to validate the
// peer's PQ-PSK binding cert extension against any per-PSK origin
// claim (e.g. FileProvider binding hint) before mixing the PSK into
// the noise state. Pass nil if no cached cert is available (first
// contact, or non-PSK subtypes); a nil cert behaves identically to
// the pre-validation lookup. Responder Machines ignore peerCert at
// NewMachine time — their cert validation runs out of the cert in
// msg1's payload, fed back to the lookup via injectResponderPSK.
func NewMachine(
	version cert.Version,
	getCred GetCredentialFunc,
	verifier CertVerifier,
	allocIndex IndexAllocator,
	initiator bool,
	subtype header.MessageSubType,
	peerStaticPubKey []byte,
	peerCert cert.Certificate,
) (*Machine, error) {
	info, err := subtypeInfoFor(subtype)
	if err != nil {
		return nil, err
	}

	cred := getCred(version)
	if cred == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCredential, version)
	}

	hs, err := cred.buildHandshakeState(initiator, info.pattern, info.presharedKeyPlacement, peerStaticPubKey, peerCert)
	if err != nil {
		return nil, fmt.Errorf("build noise state: %w", err)
	}

	return &Machine{
		hs:           hs,
		subtype:      subtype,
		msgs:         info.msgs,
		pskPlacement: info.presharedKeyPlacement,
		cred:         cred,
		getCred:      getCred,
		allocIndex:   allocIndex,
		verifier:     verifier,
		myVersion:    version,
		result: &Result{
			Initiator: initiator,
			Cipher:    cred.cipherSuite,
			Subtype:   subtype,
		},
	}, nil
}

// Failed returns true if the Machine is in an unrecoverable state.
func (m *Machine) Failed() bool {
	return m.failed
}

// Subtype returns the handshake subtype this Machine was built for.
func (m *Machine) Subtype() header.MessageSubType {
	return m.subtype
}

// MessageIndex returns the noise handshake message index, which equals the
// wire counter of the most recently sent or received message.
func (m *Machine) MessageIndex() int {
	return m.hs.MessageIndex()
}

// SetResponderPSKChooser installs the previous-epoch preference
// callback. Responder-side only; on an initiator the chooser is never
// consulted. Must be called before ProcessPacket.
func (m *Machine) SetResponderPSKChooser(fn func(peerStaticPubKey []byte) bool) {
	m.pskChooser = fn
}

// UsedPreviousPSK reports whether the responder injected the
// previous-epoch PSK (epoch-skew healing path).
func (m *Machine) UsedPreviousPSK() bool { return m.usedPrevPSK }

// SwapPSK replaces the preshared key on a live initiator machine that
// is waiting for msg2. flynn/noise checkpoints and rolls back the
// symmetric state on a failed ReadMessage and SetPresharedKey copies
// its input, so after a msg2 AEAD failure the caller may SwapPSK and
// re-feed the SAME msg2 packet — a zero-round-trip retry under a
// different PSK epoch. One swap per machine. The caller retains
// ownership of psk and should wipe it after the call.
func (m *Machine) SwapPSK(psk []byte) error {
	if m.failed {
		return ErrMachineFailed
	}
	if !m.result.Initiator {
		return fmt.Errorf("SwapPSK: initiator only")
	}
	if m.pskPlacement != 2 {
		return fmt.Errorf("SwapPSK: psk placement %d, want 2", m.pskPlacement)
	}
	if m.hs.MessageIndex() != 1 {
		return fmt.Errorf("SwapPSK: machine not waiting for msg2 (index %d)", m.hs.MessageIndex())
	}
	if m.pskSwapped {
		return fmt.Errorf("SwapPSK: already swapped once")
	}
	if len(psk) != 32 {
		return fmt.Errorf("SwapPSK: psk is %d bytes, want 32", len(psk))
	}
	if err := m.hs.SetPresharedKey(psk); err != nil {
		return fmt.Errorf("SwapPSK: %w", err)
	}
	m.pskSwapped = true
	return nil
}

// requireComplete checks that both a peer cert and payload have been received.
// Marks the machine as failed if not.
func (m *Machine) requireComplete() error {
	if !m.payloadSet || !m.remoteCertSet {
		m.failed = true
		return ErrIncompleteHandshake
	}
	return nil
}

// myMsgFlags returns the flags for the current outgoing message.
func (m *Machine) myMsgFlags() msgFlags {
	idx := m.hs.MessageIndex()
	if idx < len(m.msgs) {
		return m.msgs[idx]
	}
	return msgFlags{}
}

// peerMsgFlags returns the flags for the message we just read.
func (m *Machine) peerMsgFlags() msgFlags {
	idx := m.hs.MessageIndex() - 1
	if idx >= 0 && idx < len(m.msgs) {
		return m.msgs[idx]
	}
	return msgFlags{}
}

// Initiate produces the first handshake message. Only valid for initiators,
// and must be called exactly once before ProcessPacket.
//
// out is a destination buffer the message is appended to and returned. Pass
// nil to allocate fresh, or pass a re-used buffer sliced to length 0 (e.g.
// buf[:0]) with sufficient capacity to avoid allocation.
//
// An error return may not indicate a fatal condition, check Failed() to
// determine if the Machine can still be used.
func (m *Machine) Initiate(out []byte) ([]byte, error) {
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

	// At MessageIndex=0 with RemoteIndex still zero, buildResponse produces
	// header counter 1 and remote index 0, which is what the initial message needs.
	out, _, _, err := m.buildResponse(out)
	if err != nil {
		m.failed = true
		return nil, err
	}
	return out, nil
}

// ProcessPacket handles an incoming handshake message. It advances the Noise
// state, validates the peer certificate via the verifier, and optionally
// produces a response.
//
// out is a destination buffer the response is appended to and returned. Pass
// nil to allocate fresh, or pass a re-used buffer sliced to length 0 (e.g.
// buf[:0]) with sufficient capacity to avoid allocation. The returned slice
// is nil when no outgoing message is produced (handshake complete on this
// side, or final message of a multi-message pattern).
//
// Returns a non-nil Result when the handshake is complete.
// An error return may not indicate a fatal condition, check Failed() to
// determine if the Machine can still be used.
func (m *Machine) ProcessPacket(out, packet []byte) ([]byte, *Result, error) {
	if m.failed {
		return nil, nil, ErrMachineFailed
	}
	if len(packet) < header.Len {
		return nil, nil, ErrPacketTooShort
	}
	// Reject packets whose subtype doesn't match the one this Machine was
	// built for. A pending handshake that suddenly receives a different
	// subtype on its index is either a stray packet that matched by chance
	// or a peer protocol violation; drop it without failing the Machine so
	// the legitimate retransmit can still complete.
	if header.MessageSubType(packet[1]) != m.subtype {
		return nil, nil, ErrSubtypeMismatch
	}
	if m.result.Initiator && m.hs.MessageIndex() == 0 {
		m.failed = true
		return nil, nil, ErrInitiateNotCalled
	}

	// The (eKey, dKey) ordering here is correct for IX, where the initiator
	// completes the handshake by reading the responder's stage-2 message.
	// noise returns (cs1, cs2) where cs1 is the initiator->responder cipher.
	// For 3-message patterns where a responder finishes by reading the final
	// message, this ordering would be wrong; revisit when XX/pqIX lands.
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

	// If ReadMessage derived keys, the handshake is complete. Noise should
	// always produce both keys together; asymmetry is a protocol invariant
	// violation.
	if eKey != nil || dKey != nil {
		if eKey == nil || dKey == nil {
			m.failed = true
			return nil, nil, ErrAsymmetricCipherKeys
		}
		if err := m.requireComplete(); err != nil {
			return nil, nil, err
		}
		return nil, m.completed(eKey, dKey), nil
	}

	// Responder side, psk2: ReadMessage on msg1 has populated hs with the
	// initiator's static public key. Look up the matching per-peer PSK and
	// inject it before building msg2 so the psk token at the end of msg2
	// has key material to mix. A missing PSK is fatal — falling back to a
	// no-PSK msg2 would silently downgrade the handshake.
	if !m.result.Initiator && m.pskPlacement == 2 && !m.pskInjected {
		if err := m.injectResponderPSK(); err != nil {
			m.failed = true
			return nil, nil, err
		}
	}

	// ReadMessage didn't complete, produce the next outgoing message
	out, dk, ek, err := m.buildResponse(out)
	if err != nil {
		m.failed = true
		return nil, nil, err
	}

	if ek != nil || dk != nil {
		if ek == nil || dk == nil {
			m.failed = true
			return nil, nil, ErrAsymmetricCipherKeys
		}
		if err := m.requireComplete(); err != nil {
			return nil, nil, err
		}
		return out, m.completed(ek, dk), nil
	}

	return out, nil, nil
}

// injectResponderPSK looks up the per-peer PSK for the initiator's static
// public key (just learned from msg1) and installs it on the noise state so
// the psk token at the end of msg2 has key material to mix. Called only on
// the responder side at psk placement 2; idempotent.
//
// processPayload has already validated the peer's certificate by the time
// we get here (the IXPSK2 layout puts the cert on msg1, and ProcessPacket
// calls processPayload before injectResponderPSK), so m.result.RemoteCert
// is non-nil and safe to pass through to LookupPSK for cert-extension
// binding checks. If validation refuses the PSK (returning nil under
// enforce mode), we fail closed here — there's no fallback path from
// "responder has decided to do IXPSK2" back down to IXPSK0 mid-flight.
func (m *Machine) injectResponderPSK() error {
	peerStatic := m.hs.PeerStatic()
	if len(peerStatic) == 0 {
		return fmt.Errorf("psk2 responder: no peer static after msg1 read")
	}
	var peerCert cert.Certificate
	if m.result != nil && m.result.RemoteCert != nil {
		peerCert = m.result.RemoteCert.Certificate
	}
	var psk []byte
	if m.pskChooser != nil && m.pskChooser(peerStatic) {
		// Epoch-skew hint: the initiator likely holds our previous
		// epoch (it just rejected a current-epoch msg2). Prefer the
		// previous PSK; fall back to current when no rotation has been
		// observed for this peer.
		psk = m.cred.LookupPSKPrev(peerStatic, peerCert)
		m.usedPrevPSK = psk != nil
	}
	if psk == nil {
		psk = m.cred.LookupPSK(peerStatic, peerCert)
	}
	if psk == nil {
		return fmt.Errorf("%w %x", ErrResponderPSKMissing, peerStatic)
	}
	// SetPresharedKey enforces 32 bytes anyway; pre-check so the error
	// names the lookup as the source of the bad material.
	if len(psk) != 32 {
		return fmt.Errorf("psk2 responder: psk lookup for peer %x returned %d bytes, want 32", peerStatic, len(psk))
	}
	if err := m.hs.SetPresharedKey(psk); err != nil {
		return fmt.Errorf("psk2 responder: SetPresharedKey: %w", err)
	}
	wipeBytes(psk)
	m.pskInjected = true
	return nil
}

func (m *Machine) completed(eKey, dKey *noise.CipherState) *Result {
	m.result.EKey = eKey
	m.result.DKey = dKey
	m.result.MessageIndex = uint64(m.hs.MessageIndex())
	return m.result
}

func (m *Machine) processPayload(msg []byte, flags msgFlags) error {
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
		var remoteIndex uint32
		if m.result.Initiator {
			remoteIndex = payload.ResponderIndex
		} else {
			remoteIndex = payload.InitiatorIndex
		}
		// The payload presence check above can be satisfied by Time alone, so a payload
		// could still carry a zero index here. We need to reject it.
		if remoteIndex == 0 {
			m.failed = true
			return ErrInvalidRemoteIndex
		}
		m.result.RemoteIndex = remoteIndex
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

func (m *Machine) validateCert(payload Payload) error {
	cred := m.getCred(m.myVersion)
	if cred == nil {
		m.failed = true
		return fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}
	rc, err := cert.Recombine(
		cert.Version(payload.CertVersion),
		payload.Cert,
		m.hs.PeerStatic(),
		cred.Cert.Curve(),
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

func (m *Machine) marshalOutgoing(flags msgFlags) ([]byte, error) {
	if !flags.expectsPayload && !flags.expectsCert {
		return nil, nil
	}

	var p Payload
	if flags.expectsPayload {
		if !m.indexAllocated {
			index, err := m.allocIndex()
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrIndexAllocation, err)
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
		if cred == nil {
			return nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
		}
		p.Cert = cred.Bytes
		p.CertVersion = uint32(cred.Cert.Version())
		m.result.MyCert = cred.Cert
	}

	return MarshalPayload(nil, p), nil
}

func (m *Machine) buildResponse(out []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extend out by header.Len to make room for the header. slices.Grow is a
	// no-op when the cap is already sufficient (the zero-copy case where the
	// caller passed a pre-sized buffer). header.Encode overwrites the new
	// bytes, so they don't need to be zeroed.
	start := len(out)
	out = slices.Grow(out, header.Len)[:start+header.Len]
	header.Encode(
		out[start:],
		header.Version, header.Handshake, m.subtype,
		m.result.RemoteIndex,
		uint64(m.hs.MessageIndex()+1),
	)

	// noise.WriteMessage appends the encrypted handshake message to out,
	// reusing capacity when present.
	//
	// The (dKey, eKey) ordering here is correct for IX, where the responder
	// completes the handshake by writing the stage-2 message. noise returns
	// (cs1, cs2) where cs1 is the initiator->responder cipher (which is the
	// responder's decrypt key). For 3-message patterns where an initiator
	// finishes by writing the final message, this ordering would be wrong;
	// revisit when XX/pqIX lands.
	out, dKey, eKey, err := m.hs.WriteMessage(out, hsBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("noise WriteMessage: %w", err)
	}

	return out, dKey, eKey, nil
}
