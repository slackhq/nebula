package handshake

import "errors"

var (
	ErrInitiateOnResponder     = errors.New("initiate called on responder")
	ErrInitiateAlreadyCalled   = errors.New("initiate already called")
	ErrInitiateNotCalled       = errors.New("initiate must be called before ProcessPacket for initiators")
	ErrPacketTooShort          = errors.New("packet too short")
	ErrPublicKeyMismatch       = errors.New("public key mismatch between certificate and handshake")
	ErrIncompleteHandshake     = errors.New("handshake completed without receiving required content")
	ErrMachineFailed           = errors.New("handshake machine has failed")
	ErrUnknownSubtype          = errors.New("unknown handshake subtype")
	ErrMissingContent          = errors.New("expected handshake content but message was empty")
	ErrUnexpectedContent       = errors.New("received unexpected handshake content")
	ErrIndexAllocation         = errors.New("failed to allocate local index")
	ErrNoCredential            = errors.New("no handshake credential available for cert version")
	ErrAsymmetricCipherKeys    = errors.New("noise produced only one cipher key")
	ErrMultiMessageUnsupported = errors.New("multi-message handshake patterns are not yet supported by the manager")
	ErrSubtypeMismatch         = errors.New("packet subtype does not match handshake machine subtype")
)
