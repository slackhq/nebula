//go:build rosenpass_embedded

package rposvc

import "net"

// ServiceAPI is the subset of *Service that Coordinator depends on.
// Defined as an interface so tests can inject a fake Service without
// keypair generation or a UDP listener.
//
// *Service satisfies this interface; production callers continue to
// pass a concrete *Service and the compile-time assertion below keeps
// the two definitions in lock-step.
type ServiceAPI interface {
	AddPeer(peerStaticPubKey, rosenpassPubKey []byte, endpoint *net.UDPAddr) error
	RemovePeer(peerStaticPubKey []byte)
	PublicKey() []byte
	PublicKeyHex() string
}

// Compile-time assertion that *Service satisfies ServiceAPI.
var _ ServiceAPI = (*Service)(nil)
