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

// NewSender prepares pkt, a handshake message as it would travel unfragmented,
// Nebula header included, for sending as fragments. Every fragment carries that
// header with the fragmented form of its subtype; fragID is the sender's local
// index. The Sender keeps pkt, which must not change while it is in use.
func NewSender(pkt []byte, fragID uint32) (*Sender, error) {
	var h header.H
	if err := h.Parse(pkt); err != nil {
		return nil, err
	}
	st, ok := header.FragmentedSubtype(h.Subtype)
	if !ok {
		return nil, ErrSubtype
	}
	return newSender(pkt[header.Len:], st, h.RemoteIndex, h.MessageCounter, fragID)
}

// newSender prepares msg, the message alone, for sending. subtype, remoteIndex
// and counter fill the Nebula header of every fragment.
func newSender(msg []byte, subtype header.MessageSubType, remoteIndex uint32, counter uint64, fragID uint32) (*Sender, error) {
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
	// One allocation backs every packet of the attempt.
	pktCap := header.Len + HeaderLen + CookieLen + s.enc.Layout().SymbolSize
	buf := make([]byte, (k+repair)*pktCap)
	for i := range k + repair {
		p, err := s.packet(buf[i*pktCap:i*pktCap:(i+1)*pktCap], s.next)
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

// packet builds the packet for the symbol at index in the capacity of p, which
// must have room for it.
func (s *Sender) packet(p []byte, index int) ([]byte, error) {
	l := s.enc.Layout()
	p = header.Encode(p[:header.Len], header.Version, header.Handshake, s.subtype, s.remoteIndex, s.counter)
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
