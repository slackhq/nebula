package virtio

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNetHdr_Size(t *testing.T) {
	assert.EqualValues(t, NetHdrSize, unsafe.Sizeof(NetHdr{}))
}

func TestNetHdr_Encoding(t *testing.T) {
	vnethdr := NetHdr{
		Flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		GSOType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
		HdrLen:     42,
		GSOSize:    1472,
		CsumStart:  34,
		CsumOffset: 6,
		NumBuffers: 16,
	}

	buf := make([]byte, NetHdrSize)
	require.NoError(t, vnethdr.Encode(buf))

	assert.Equal(t, []byte{
		0x01, 0x05,
		0x2a, 0x00,
		0xc0, 0x05,
		0x22, 0x00,
		0x06, 0x00,
		0x10, 0x00,
	}, buf)

	var decoded NetHdr
	require.NoError(t, decoded.Decode(buf))

	assert.Equal(t, vnethdr, decoded)
}
