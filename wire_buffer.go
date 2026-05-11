package nebula

import (
	"io"
	"sync"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay"
)

// WireBuffer is the per-goroutine working set for processing one IP packet
// through the data plane. It owns:
//
//   - The IP-payload byte buffer used to hold the current inbound or
//     outbound packet, with prefixLen bytes of slack at the front for
//     the BSD AF_INET protocol-family marker.
//   - The fwPacket scratch parsed by newPacket().
//   - The 12-byte AEAD nonce scratch.
//   - The header.H parse target used by the receive path.
//   - An mtu-sized wire-output scratch for sendNoMetrics and for building
//     reject packets.
//
// One WireBuffer is allocated per data-plane goroutine (listenIn for the
// TUN-side, listenOut for the UDP-side) and reused for every packet. No
// per-packet allocation. Future GRO/GSO/TSO and reliable-transport work
// will likely extend this to carry batch state and fragment metadata.
//
// The TUN protocol-family prefix is handled here, not in the overlay
// package. On BSDs the kernel writes the 4-byte marker into the slack on
// read, and we stamp it into the slack before write. On linux/windows
// /userspace devices prefixLen is 0 and the slack is empty.
type WireBuffer struct {
	// FwPacket is the parsed IP packet metadata (5-tuple, fragment flags,
	// etc.) populated by newPacket().
	FwPacket *firewall.Packet
	// NB is a 12-byte scratch the AEAD uses for the nonce; reused so we
	// don't allocate one per encrypt/decrypt.
	NB []byte
	// H is the parse target for inbound nebula headers. Receive path only.
	H *header.H
	// Out is an mtu-sized wire-output scratch passed to sendNoMetrics and
	// rejectInside / rejectOutside. Sized to fit any single wire packet.
	Out []byte

	// ip is the IP-payload region: a slice of len 0, cap linkMTU sliced
	// from raw at offset prefixLen. The current packet (if any) is
	// ip[:bodyN]. The TUN prefix slack lives at raw[0:prefixLen] just
	// before ip.
	ip []byte
	// raw is the backing slab. Layout:
	//   [prefixLen bytes prefix slack | linkMTU bytes IP region | outSize bytes Out scratch]
	// Holding it lets ReadIPFromTUN / WriteIPToTUN address the slack
	// region directly.
	raw       []byte
	prefixLen int
	bodyN     int
}

// NewWireBuffer returns a buffer sized to hold any single IP packet up to
// linkMTU, plus a disjoint wire-output scratch sliced from the same backing
// slab (the AEAD's Seal contract requires plaintext and dst not to partially
// overlap, and keeping them in one slab gives a single allocation per
// goroutine). Out is sized for the relay worst case
// (linkMTU + 2*header.Len + 2*AEADOverhead).
//
// prefixLen is the number of bytes the destination tun device prepends/
// expects on each IP packet (overlay.Device.TunPrefixLen). On BSDs this
// is 4 (AF_INET marker); on linux/windows/userspace devices it is 0.
func NewWireBuffer(linkMTU, prefixLen int) *WireBuffer {
	outSize := linkMTU + 2*header.Len + 2*AEADOverhead
	raw := make([]byte, prefixLen+linkMTU+outSize)
	outStart := prefixLen + linkMTU
	return &WireBuffer{
		FwPacket:  &firewall.Packet{},
		NB:        make([]byte, NonceSize),
		H:         &header.H{},
		Out:       raw[outStart : outStart : outStart+outSize],
		ip:        raw[prefixLen:prefixLen:outStart],
		raw:       raw,
		prefixLen: prefixLen,
	}
}

// Reset clears the body-length record so the buffer is ready for another
// recv (e.g. relay-receive recursion before a nested decrypt).
func (b *WireBuffer) Reset() { b.bodyN = 0 }

// IPPacket returns the IP packet currently held in the payload region (after
// a successful ReadIPFromTUN or DecryptDatagram). The slice aliases the
// buffer; do not retain past the next operation.
func (b *WireBuffer) IPPacket() []byte {
	return b.ip[:b.bodyN]
}

// Seal stamps a nebula header at the front of buf.Out and AEAD-seals p as the
// payload, treating the header as additional authenticated data. The lock
// scope around counter increment + encrypt matches what goboring AESGCMTLS
// requires; non-boring builds skip the lock.
//
// Returns the wire bytes (header || ciphertext || tag), aliased to buf.Out.
// The slice is invalidated by the next Seal* call on this buffer.
func (b *WireBuffer) Seal(ci *ConnectionState, t header.MessageType, st header.MessageSubType, remoteIndex uint32, p []byte) ([]byte, error) {
	return b.sealInto(b.Out[:cap(b.Out)], ci, t, st, remoteIndex, p)
}

// SealForRelay is like Seal but reserves header.Len bytes of slack at the front
// of buf.Out for an outer relay header. The inner header + ciphertext lands at
// offset header.Len so a follow-up SealRelayInPlace can stamp the outer header
// without copying. Use this when the caller may need to wrap the result in a
// relay envelope after the fact.
func (b *WireBuffer) SealForRelay(ci *ConnectionState, t header.MessageType, st header.MessageSubType, remoteIndex uint32, p []byte) ([]byte, error) {
	return b.sealInto(b.Out[header.Len:cap(b.Out)], ci, t, st, remoteIndex, p)
}

func (b *WireBuffer) sealInto(out []byte, ci *ConnectionState, t header.MessageType, st header.MessageSubType, remoteIndex uint32, p []byte) ([]byte, error) {
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Lock()
	}
	c := ci.messageCounter.Add(1)
	out = header.Encode(out, header.Version, t, st, remoteIndex, c)
	out, err := ci.eKey.EncryptDanger(out, out, p, c, b.NB)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	return out, err
}

// SealRelayInPlace wraps an inner message that is already staged at
// buf.Out[header.Len:header.Len+innerLen] (either from a SealForRelay encrypt
// or from a copy via the SendVia entry point). It stamps the outer relay
// header into buf.Out[:header.Len] and AAD-only seals over the entire region,
// producing the wire bytes for the relay tunnel.
//
// Returns the wire bytes aliased to buf.Out; invalidated by the next Seal*
// call on this buffer.
func (b *WireBuffer) SealRelayInPlace(ci *ConnectionState, remoteIndex uint32, innerLen int) ([]byte, error) {
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Lock()
	}
	c := ci.messageCounter.Add(1)
	out := b.Out[:cap(b.Out)]
	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, remoteIndex, c)
	out = out[:header.Len+innerLen]
	out, err := ci.eKey.EncryptDanger(out, out, nil, c, b.NB)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	return out, err
}

// StageRelayInner copies ad into the inner-payload slot at buf.Out[header.Len:]
// so SealRelayInPlace can wrap it on the next call. Used by SendVia when ad
// did not come from a prior SealForRelay (e.g. a handshake message being
// forwarded through a relay tunnel without our own encryption).
func (b *WireBuffer) StageRelayInner(ad []byte) int {
	return copy(b.Out[header.Len:cap(b.Out)], ad)
}

// ReadIPFromTUN reads one IP packet from r into the payload region and
// updates bodyN. On BSDs the kernel writes its 4-byte protocol-family
// marker into the slack at raw[0:prefixLen] and the IP packet at
// raw[prefixLen:prefixLen+n]; we hand it the slack-prefixed slice so
// the kernel can do this in one syscall with no copy. On linux/windows/
// userspace devices prefixLen is 0 and the slack is empty.
func (b *WireBuffer) ReadIPFromTUN(r io.Reader) (int, error) {
	n, err := r.Read(b.raw[:b.prefixLen+cap(b.ip)])
	if err != nil {
		b.bodyN = 0
		return 0, err
	}
	if n < b.prefixLen {
		b.bodyN = 0
		return 0, nil
	}
	b.bodyN = n - b.prefixLen
	return b.bodyN, nil
}

// WriteIPToTUN writes the IP packet currently in the payload region to w.
// On BSDs we stamp the protocol-family marker into the slack at
// raw[0:prefixLen] in place and write the entire slack+IP region in a
// single syscall, so the kernel sees [marker][ip] back to back without a
// userspace copy. On linux/windows/userspace devices the slack is empty
// and we just write the IP region.
func (b *WireBuffer) WriteIPToTUN(w io.Writer) (int, error) {
	out := b.raw[:b.prefixLen+b.bodyN]
	if b.prefixLen > 0 {
		if err := overlay.StampTunPrefix(out); err != nil {
			return 0, err
		}
	}
	return w.Write(out)
}

// DecryptDatagram decrypts an inbound UDP packet into the payload region.
func (b *WireBuffer) DecryptDatagram(ci *ConnectionState, packet []byte, mc uint64) error {
	dst, err := ci.dKey.DecryptDanger(b.ip[:0], packet[:header.Len], packet[header.Len:], mc, b.NB)
	if err != nil {
		b.bodyN = 0
		return err
	}
	b.bodyN = len(dst)
	return nil
}

// DecryptForHandler decrypts an inbound UDP packet (lighthouse, test,
// control, close-tunnel) into the payload region and returns the plaintext
// slice for the in-process handler. Returned slice aliases the buffer.
func (b *WireBuffer) DecryptForHandler(ci *ConnectionState, packet []byte, mc uint64) ([]byte, error) {
	dst, err := ci.dKey.DecryptDanger(b.ip[:0], packet[:header.Len], packet[header.Len:], mc, b.NB)
	if err != nil {
		b.bodyN = 0
		return nil, err
	}
	b.bodyN = len(dst)
	return dst, nil
}

// WireBufferAllocator hands out reusable WireBuffers for cold callers that
// don't own a long-lived per-goroutine buffer (control plane, relay manager,
// connection manager teardown, etc.). Hot-path goroutines hold their own
// buffer for the life of the goroutine and don't need to acquire one.
type WireBufferAllocator interface {
	Acquire() *WireBuffer
	Release(*WireBuffer)
}

// wireBufferPool is a sync.Pool-backed WireBufferAllocator. The pool is
// keyed off a single linkMTU and prefixLen; cold callers send across the
// data-plane mtu and target the same Device, so we size the pool's
// buffers the same way.
type wireBufferPool struct {
	pool sync.Pool
}

func NewWireBufferPool(linkMTU, prefixLen int) *wireBufferPool {
	return &wireBufferPool{
		pool: sync.Pool{
			New: func() any {
				return NewWireBuffer(linkMTU, prefixLen)
			},
		},
	}
}

func (p *wireBufferPool) Acquire() *WireBuffer {
	return p.pool.Get().(*WireBuffer)
}

func (p *wireBufferPool) Release(b *WireBuffer) {
	b.Reset()
	p.pool.Put(b)
}
