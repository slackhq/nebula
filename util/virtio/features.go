package virtio

// Feature contains feature bits that describe a virtio device or driver.
type Feature uint64

// Device-independent feature bits.
//
// Source: https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-6600006
const (
	// FeatureIndirectDescriptors indicates that the driver can use descriptors
	// with an additional layer of indirection.
	FeatureIndirectDescriptors Feature = 1 << 28

	// FeatureVersion1 indicates compliance with version 1.0 of the virtio
	// specification.
	FeatureVersion1 Feature = 1 << 32
)

// Feature bits for networking devices.
//
// Source: https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2200003
const (
	// FeatureNetDeviceCsum indicates that the device can handle packets with
	// partial checksum (checksum offload).
	FeatureNetDeviceCsum Feature = 1 << 0

	// FeatureNetDriverCsum indicates that the driver can handle packets with
	// partial checksum.
	FeatureNetDriverCsum Feature = 1 << 1

	// FeatureNetCtrlDriverOffloads indicates support for dynamic offload state
	// reconfiguration.
	FeatureNetCtrlDriverOffloads Feature = 1 << 2

	// FeatureNetMTU indicates that the device reports a maximum MTU value.
	FeatureNetMTU Feature = 1 << 3

	// FeatureNetMAC indicates that the device provides a MAC address.
	FeatureNetMAC Feature = 1 << 5

	// FeatureNetDriverTSO4 indicates that the driver supports the TCP
	// segmentation offload for received IPv4 packets.
	FeatureNetDriverTSO4 Feature = 1 << 7

	// FeatureNetDriverTSO6 indicates that the driver supports the TCP
	// segmentation offload for received IPv6 packets.
	FeatureNetDriverTSO6 Feature = 1 << 8

	// FeatureNetDriverECN indicates that the driver supports the TCP
	// segmentation offload with ECN for received packets.
	FeatureNetDriverECN Feature = 1 << 9

	// FeatureNetDriverUFO indicates that the driver supports the UDP
	// fragmentation offload for received packets.
	FeatureNetDriverUFO Feature = 1 << 10

	// FeatureNetDeviceTSO4 indicates that the device supports the TCP
	// segmentation offload for received IPv4 packets.
	FeatureNetDeviceTSO4 Feature = 1 << 11

	// FeatureNetDeviceTSO6 indicates that the device supports the TCP
	// segmentation offload for received IPv6 packets.
	FeatureNetDeviceTSO6 Feature = 1 << 12

	// FeatureNetDeviceECN indicates that the device supports the TCP
	// segmentation offload with ECN for received packets.
	FeatureNetDeviceECN Feature = 1 << 13

	// FeatureNetDeviceUFO indicates that the device supports the UDP
	// fragmentation offload for received packets.
	FeatureNetDeviceUFO Feature = 1 << 14

	// FeatureNetMergeRXBuffers indicates that the driver can handle merged
	// receive buffers.
	// When this feature is negotiated, devices may merge multiple descriptor
	// chains together to transport large received packets. [NetHdr.NumBuffers]
	// will then contain the number of merged descriptor chains.
	FeatureNetMergeRXBuffers Feature = 1 << 15

	// FeatureNetStatus indicates that the device configuration status field is
	// available.
	FeatureNetStatus Feature = 1 << 16

	// FeatureNetCtrlVQ indicates that a control channel virtqueue is
	// available.
	FeatureNetCtrlVQ Feature = 1 << 17

	// FeatureNetCtrlRX indicates support for RX mode control (e.g. promiscuous
	// or all-multicast) for packet receive filtering.
	FeatureNetCtrlRX Feature = 1 << 18

	// FeatureNetCtrlVLAN indicates support for VLAN filtering through the
	// control channel.
	FeatureNetCtrlVLAN Feature = 1 << 19

	// FeatureNetDriverAnnounce indicates that the driver can send gratuitous
	// packets.
	FeatureNetDriverAnnounce Feature = 1 << 21

	// FeatureNetMQ indicates that the device supports multiqueue with automatic
	// receive steering.
	FeatureNetMQ Feature = 1 << 22

	// FeatureNetCtrlMACAddr indicates that the MAC address can be set through
	// the control channel.
	FeatureNetCtrlMACAddr Feature = 1 << 23

	// FeatureNetDeviceUSO indicates that the device supports the UDP
	// segmentation offload for received packets.
	FeatureNetDeviceUSO Feature = 1 << 56

	// FeatureNetHashReport indicates that the device can report a per-packet
	// hash value and type.
	FeatureNetHashReport Feature = 1 << 57

	// FeatureNetDriverHdrLen indicates that the driver can provide the exact
	// header length value (see [NetHdr.HdrLen]).
	// Devices may benefit from knowing the exact header length.
	FeatureNetDriverHdrLen Feature = 1 << 59

	// FeatureNetRSS indicates that the device supports RSS (receive-side
	// scaling) with configurable hash parameters.
	FeatureNetRSS Feature = 1 << 60

	// FeatureNetRSCExt indicates that the device can process duplicated ACKs
	// and report the number of coalesced segments and duplicated ACKs.
	FeatureNetRSCExt Feature = 1 << 61

	// FeatureNetStandby indicates that the device may act as a standby for a
	// primary device with the same MAC address.
	FeatureNetStandby Feature = 1 << 62

	// FeatureNetSpeedDuplex indicates that the device can report link speed and
	// duplex mode.
	FeatureNetSpeedDuplex Feature = 1 << 63
)
