package fragment

import (
	"errors"
	"math"

	"github.com/slackhq/nebula/handshake/fec"
	"github.com/slackhq/nebula/header"
)

// DefaultRepair is the starting number of repair symbols per attempt for a
// message of k data symbols. Small messages get proportionally more repair.
func DefaultRepair(k int) int {
	return max(2, (k+2)/3)
}

// Sender produces the fragment packets of one outgoing handshake message.
//
// The first attempt sends the K data symbols followed by repair symbols. Every
// later attempt sends symbols with indexes the receiver has not been offered yet,
// so whatever it already holds still counts toward K. Symbols are a deterministic
// function of the message, which keeps retransmits idempotent. Once all
// fec.MaxSymbols indexes are used the sequence wraps and repeats.
//
// A Sender is not safe for concurrent use.
type Sender struct {
	enc         *fec.Encoder
	subtype     header.MessageSubType
	remoteIndex uint32
	counter     uint64
	fragID      uint32
	next        int
	cookie      *Cookie
}

// NewSender prepares msg for sending. subtype, remoteIndex and counter fill the
// Nebula header of every fragment; fragID is the sender's local index. The
// Sender keeps msg, which must not change while it is in use.
func NewSender(msg []byte, subtype header.MessageSubType, remoteIndex uint32, counter uint64, fragID uint32) (*Sender, error) {
	if len(msg) == 0 || len(msg) > math.MaxUint16 {
		return nil, ErrMsgLen
	}
	if fragID == 0 {
		return nil, ErrFragID
	}
	enc, err := fec.NewEncoder(msg, MaxSymbolSize)
	if err != nil {
		return nil, err
	}
	return &Sender{
		enc:         enc,
		subtype:     subtype,
		remoteIndex: remoteIndex,
		counter:     counter,
		fragID:      fragID,
	}, nil
}

func (s *Sender) Layout() fec.Layout {
	return s.enc.Layout()
}

// SetNext sets the index the next attempt starts from, so a sender rebuilt from
// a cached message can carry on offering fresh symbols.
func (s *Sender) SetNext(index int) {
	s.next = ((index % fec.MaxSymbols) + fec.MaxSymbols) % fec.MaxSymbols
}

// SetCookie attaches a cookie from a responder under load to every later packet.
func (s *Sender) SetCookie(c Cookie) {
	s.cookie = &c
}

// Next returns the index the next attempt starts from.
func (s *Sender) Next() int {
	return s.next
}

// Attempt returns the packets for one transmission attempt carrying K+repair
// symbols. now should be sent immediately and later after the repair delay, so
// a tail drop at the end of the first burst does not also take the repair.
func (s *Sender) Attempt(repair int) (now, later [][]byte, err error) {
	if repair < 0 {
		return nil, nil, errors.New("negative repair count")
	}
	k := s.enc.Layout().K
	now = make([][]byte, 0, k)
	later = make([][]byte, 0, repair)
	for i := range k + repair {
		p, err := s.packet(s.next)
		if err != nil {
			return nil, nil, err
		}
		s.next = (s.next + 1) % fec.MaxSymbols
		if i < k {
			now = append(now, p)
		} else {
			later = append(later, p)
		}
	}
	return now, later, nil
}

func (s *Sender) packet(index int) ([]byte, error) {
	l := s.enc.Layout()
	p := make([]byte, header.Len, header.Len+HeaderLen+CookieLen+l.SymbolSize)
	header.Encode(p, header.Version, header.Handshake, s.subtype, s.remoteIndex, s.counter)
	h := Header{
		FragID: s.fragID,
		MsgLen: uint16(l.MsgLen),
		Index:  uint8(index),
	}
	if s.cookie != nil {
		h.Flags |= FlagCookie
		h.Cookie = *s.cookie
	}
	p = h.Encode(p)
	return s.enc.Symbol(p, index)
}
