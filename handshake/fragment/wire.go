// Package fragment carries handshake messages that do not fit in one UDP
// packet. A message is Reed-Solomon coded into equally sized symbols (see
// handshake/fec) and each symbol travels in its own packet:
//
//	Nebula header (16) | Fragment header (8) | [cookie (16)] | symbol
//
// The fragment header is FragID u32 | MsgLen u16 | Index u8 | Flags u8, all big
// endian. Both ends derive the symbol layout from MsgLen, so any MsgLen-derived
// value never has to be sent. FlagCookie marks a cookie a responder under load
// asked for; room for it is always reserved, so a fragment never outgrows
// MaxPacketLen.
package fragment

import (
	"encoding/binary"
	"errors"

	"github.com/slackhq/nebula/handshake/fec"
	"github.com/slackhq/nebula/header"
)

const (
	// HeaderLen is the size of the fragment header that follows the Nebula header.
	HeaderLen = 8

	// CookieLen is the size of the cookie a fragment carries when FlagCookie is set.
	CookieLen = 16

	// FlagCookie marks a fragment that carries a cookie after its header.
	FlagCookie uint8 = 0x01

	// MaxPacketLen bounds every fragment packet, Nebula header included. A relayed
	// fragment gains a 16 byte header and a 16 byte tag, which lands exactly on
	// the 1232 byte UDP payload available on an IPv6 minimum MTU path.
	MaxPacketLen = 1200

	// MaxSymbolSize is the largest symbol that fits in MaxPacketLen alongside a cookie.
	MaxSymbolSize = MaxPacketLen - header.Len - HeaderLen - CookieLen
)

var (
	ErrShortFragment = errors.New("fragment is too short")
	ErrFragID        = errors.New("fragment has a zero FragID")
	ErrMsgLen        = errors.New("fragment has a zero MsgLen")
	ErrFlags         = errors.New("fragment has reserved flags set")
	ErrNoCookie      = errors.New("fragment is too short for its cookie")
	ErrSymbolSize    = errors.New("fragment symbol size does not match its MsgLen")
)

// Cookie proves a sender received a responder's reply at its address.
type Cookie [CookieLen]byte

// Header is the fragment header.
type Header struct {
	FragID uint32 // the sender's local index for this handshake, never zero
	MsgLen uint16 // length of the whole message
	Index  uint8  // symbol index, data below K and repair from K
	Flags  uint8  // FlagCookie, other bits reserved and zero
	Cookie Cookie // valid when Flags has FlagCookie
}

func (h Header) HasCookie() bool {
	return h.Flags&FlagCookie != 0
}

// Encode appends the header, and its cookie if it has one, to b.
func (h Header) Encode(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, h.FragID)
	b = binary.BigEndian.AppendUint16(b, h.MsgLen)
	b = append(b, h.Index, h.Flags)
	if h.HasCookie() {
		b = append(b, h.Cookie[:]...)
	}
	return b
}

// Layout returns the symbol layout the header's MsgLen implies.
func (h Header) Layout() (fec.Layout, error) {
	return fec.NewLayout(int(h.MsgLen), MaxSymbolSize)
}

// Parse validates the bytes following the Nebula header and splits them into
// the fragment header and the symbol. The symbol aliases b.
func Parse(b []byte) (Header, []byte, error) {
	if len(b) < HeaderLen {
		return Header{}, nil, ErrShortFragment
	}
	h := Header{
		FragID: binary.BigEndian.Uint32(b[0:4]),
		MsgLen: binary.BigEndian.Uint16(b[4:6]),
		Index:  b[6],
		Flags:  b[7],
	}
	if h.FragID == 0 {
		return Header{}, nil, ErrFragID
	}
	if h.MsgLen == 0 {
		return Header{}, nil, ErrMsgLen
	}
	if h.Flags&^FlagCookie != 0 {
		return Header{}, nil, ErrFlags
	}
	b = b[HeaderLen:]
	if h.HasCookie() {
		if len(b) < CookieLen {
			return Header{}, nil, ErrNoCookie
		}
		copy(h.Cookie[:], b)
		b = b[CookieLen:]
	}

	l, err := h.Layout()
	if err != nil {
		return Header{}, nil, err
	}
	sym := b
	if len(sym) != l.SymbolSize {
		return Header{}, nil, ErrSymbolSize
	}
	return h, sym, nil
}
