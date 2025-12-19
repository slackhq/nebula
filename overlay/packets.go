package overlay

//import (
//	"github.com/slackhq/nebula/util/virtio"
//)

//type VirtIOPacket struct {
//	Payload   []byte
//	Header    virtio.NetHdr
//	Chains    []uint16
//	ChainRefs [][]byte
//}
//
//func NewVIO() *VirtIOPacket {
//	out := new(VirtIOPacket)
//	out.Payload = nil
//	out.ChainRefs = make([][]byte, 0, 4)
//	out.Chains = make([]uint16, 0, 8)
//	return out
//}
//
//func (v *VirtIOPacket) Reset() {
//	v.Payload = nil
//	v.ChainRefs = v.ChainRefs[:0]
//	v.Chains = v.Chains[:0]
//}

// TunPacket is formerly VirtIOPacket
type TunPacket interface {
	SetPayload([]byte)
	GetPayload() []byte
}
type OutPacket interface {
	SetPayload([]byte)
	GetPayload() []byte
}
