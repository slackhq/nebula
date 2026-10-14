package fragment

import (
	"errors"

	"github.com/slackhq/nebula/handshake/fec"
	"github.com/slackhq/nebula/header"
)

// ErrMismatch is returned when a fragment disagrees with the message it claims to
// belong to. The caller should discard the whole assembly.
var ErrMismatch = errors.New("fragment does not match its message")

// Assembly collects the fragments of one incoming message. Its memory is bounded
// by the message length: at most K symbols are kept however many arrive.
//
// An Assembly is not safe for concurrent use.
type Assembly struct {
	fragID   uint32
	msgLen   uint16
	dec      *fec.Decoder
	received int
}

// NewAssembly starts an assembly for the message described by h. The fragment
// itself still has to be passed to Add.
func NewAssembly(h Header) (*Assembly, error) {
	dec, err := fec.NewDecoder(int(h.MsgLen), MaxSymbolSize)
	if err != nil {
		return nil, err
	}
	return &Assembly{fragID: h.FragID, msgLen: h.MsgLen, dec: dec}, nil
}

// Add records a fragment parsed by Parse. It returns true once enough symbols
// are held to call Decode.
func (a *Assembly) Add(h Header, sym []byte) (bool, error) {
	if h.FragID != a.fragID || h.MsgLen != a.msgLen {
		return a.dec.Ready(), ErrMismatch
	}
	a.received += header.Len + HeaderLen + len(sym)
	return a.dec.Add(int(h.Index), sym)
}

// wouldStore returns how many bytes Add would retain for this fragment.
func (a *Assembly) wouldStore(h Header, sym []byte) int {
	if h.FragID != a.fragID || h.MsgLen != a.msgLen || a.dec.Ready() || a.dec.Has(int(h.Index)) {
		return 0
	}
	return len(sym)
}

// Decode reconstructs the message and appends it to dst, see fec.Decoder.Decode.
// It requires Add to have reported ready.
func (a *Assembly) Decode(dst []byte) ([]byte, error) {
	return a.dec.Decode(dst)
}

// Stored returns the number of symbol bytes held.
func (a *Assembly) Stored() int {
	return a.dec.Stored() * a.dec.Layout().SymbolSize
}

// Received returns the number of packet bytes received for this message,
// duplicates included. It is the basis for the amplification budget.
func (a *Assembly) Received() int {
	return a.received
}
