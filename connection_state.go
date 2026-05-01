package nebula

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
)

const ReplayWindow = 1024

type ConnectionState struct {
	eKey           *NebulaCipherState
	dKey           *NebulaCipherState
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
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
		eKey:      NewNebulaCipherState(r.EKey),
		dKey:      NewNebulaCipherState(r.DKey),
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
