package vhostnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/slackhq/nebula/overlay/vhost"
	"github.com/slackhq/nebula/overlay/virtqueue"
	"github.com/slackhq/nebula/packet"
	"github.com/slackhq/nebula/util/virtio"
	"golang.org/x/sys/unix"
)

// ErrDeviceClosed is returned when the [Device] is closed while operations are
// still running.
var ErrDeviceClosed = errors.New("device was closed")

// The indexes for the receive and transmit queues.
const (
	receiveQueueIndex  = 0
	transmitQueueIndex = 1
)

// Device represents a vhost networking device within the kernel-level virtio
// implementation and provides methods to interact with it.
type Device struct {
	controlFD int

	ReceiveQueue  *virtqueue.SplitQueue
	TransmitQueue *virtqueue.SplitQueue
}

// NewDevice initializes a new vhost networking device within the
// kernel-level virtio implementation, sets up the virtqueues and returns a
// [Device] instance that can be used to communicate with that vhost device.
//
// There are multiple options that can be passed to this constructor to
// influence device creation:
//   - [WithQueueSize]
//   - [WithBackendFD]
//   - [WithBackendDevice]
//
// Remember to call [Device.Close] after use to free up resources.
func NewDevice(options ...Option) (*Device, error) {
	var err error
	opts := optionDefaults
	opts.apply(options)
	if err = opts.validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	dev := Device{
		controlFD: -1,
	}

	// Clean up a partially initialized device when something fails.
	defer func() {
		if err != nil {
			_ = dev.Close()
		}
	}()

	// Retrieve a new control file descriptor. This will be used to configure
	// the vhost networking device in the kernel.
	dev.controlFD, err = unix.Open("/dev/vhost-net", os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("get control file descriptor: %w", err)
	}
	if err = vhost.OwnControlFD(dev.controlFD); err != nil {
		return nil, fmt.Errorf("own control file descriptor: %w", err)
	}

	// Advertise the supported features. This isn't much for now.
	// TODO: Add feature options and implement proper feature negotiation.
	getFeatures, err := vhost.GetFeatures(dev.controlFD) //0x1033D008000 but why
	if err != nil {
		return nil, fmt.Errorf("get features: %w", err)
	}
	if getFeatures == 0 {

	}
	//const funky = virtio.Feature(1 << 27)
	//features := virtio.FeatureVersion1 | funky // | todo virtio.FeatureNetMergeRXBuffers
	features := virtio.FeatureVersion1 | virtio.FeatureNetMergeRXBuffers
	if err = vhost.SetFeatures(dev.controlFD, features); err != nil {
		return nil, fmt.Errorf("set features: %w", err)
	}

	itemSize := os.Getpagesize() * 4 //todo config

	// Initialize and register the queues needed for the networking device.
	if dev.ReceiveQueue, err = createQueue(dev.controlFD, receiveQueueIndex, opts.queueSize, itemSize); err != nil {
		return nil, fmt.Errorf("create receive queue: %w", err)
	}
	if dev.TransmitQueue, err = createQueue(dev.controlFD, transmitQueueIndex, opts.queueSize, itemSize); err != nil {
		return nil, fmt.Errorf("create transmit queue: %w", err)
	}

	// Set up memory mappings for all buffers used by the queues. This has to
	// happen before a backend for the queues can be registered.
	memoryLayout := vhost.NewMemoryLayoutForQueues(
		[]*virtqueue.SplitQueue{dev.ReceiveQueue, dev.TransmitQueue},
	)
	if err = vhost.SetMemoryLayout(dev.controlFD, memoryLayout); err != nil {
		return nil, fmt.Errorf("setup memory layout: %w", err)
	}

	// Set the queue backends. This activates the queues within the kernel.
	if err = SetQueueBackend(dev.controlFD, receiveQueueIndex, opts.backendFD); err != nil {
		return nil, fmt.Errorf("set receive queue backend: %w", err)
	}
	if err = SetQueueBackend(dev.controlFD, transmitQueueIndex, opts.backendFD); err != nil {
		return nil, fmt.Errorf("set transmit queue backend: %w", err)
	}

	// Fully populate the rx queue with available buffers which the device
	// can write new packets into.
	if err = dev.refillReceiveQueue(); err != nil {
		return nil, fmt.Errorf("refill receive queue: %w", err)
	}
	if err = dev.prefillTxQueue(); err != nil {
		return nil, fmt.Errorf("prefill tx queue: %w", err)
	}

	// Make sure to clean up even when the device gets garbage collected without
	// Close being called first.
	devPtr := &dev
	runtime.SetFinalizer(devPtr, (*Device).Close)

	return devPtr, nil
}

// refillReceiveQueue offers as many new device-writable buffers to the device
// as the queue can fit. The device will then use these to write received
// packets.
func (dev *Device) refillReceiveQueue() error {
	for {
		_, err := dev.ReceiveQueue.OfferInDescriptorChains()
		if err != nil {
			if errors.Is(err, virtqueue.ErrNotEnoughFreeDescriptors) {
				// Queue is full, job is done.
				return nil
			}
			return fmt.Errorf("offer descriptor chain: %w", err)
		}
	}
}

func (dev *Device) prefillTxQueue() error {
	for {
		dt := dev.TransmitQueue.DescriptorTable()
		for {
			x, _, err := dt.CreateDescriptorForOutputs()
			if err != nil {
				if errors.Is(err, virtqueue.ErrNotEnoughFreeDescriptors) {
					// Queue is full, job is done.
					return nil
				}
				return err
			}
			err = dev.TransmitQueue.OfferDescriptorChains([]uint16{x}, false)
			if err != nil {
				return err
			}
		}

	}
}

// Close cleans up the vhost networking device within the kernel and releases
// all resources used for it.
// The implementation will try to release as many resources as possible and
// collect potential errors before returning them.
func (dev *Device) Close() error {
	// Closing the control file descriptor will unregister all queues from the
	// kernel.
	if dev.controlFD >= 0 {
		if err := unix.Close(dev.controlFD); err != nil {
			// Return an error and do not continue, because the memory used for
			// the queues should not be released before they were unregistered
			// from the kernel.
			return fmt.Errorf("close control file descriptor: %w", err)
		}
		dev.controlFD = -1
	}

	var errs []error

	if dev.ReceiveQueue != nil {
		if err := dev.ReceiveQueue.Close(); err == nil {
			dev.ReceiveQueue = nil
		} else {
			errs = append(errs, fmt.Errorf("close receive queue: %w", err))
		}
	}

	if dev.TransmitQueue != nil {
		if err := dev.TransmitQueue.Close(); err == nil {
			dev.TransmitQueue = nil
		} else {
			errs = append(errs, fmt.Errorf("close transmit queue: %w", err))
		}
	}

	if len(errs) == 0 {
		// Everything was cleaned up. No need to run the finalizer anymore.
		runtime.SetFinalizer(dev, nil)
	}

	return errors.Join(errs...)
}

// createQueue creates a new virtqueue and registers it with the vhost device
// using the given index.
func createQueue(controlFD int, queueIndex int, queueSize int, itemSize int) (*virtqueue.SplitQueue, error) {
	queue, err := virtqueue.NewSplitQueue(queueSize, itemSize)
	if err != nil {
		return nil, fmt.Errorf("create virtqueue: %w", err)
	}
	if err = vhost.RegisterQueue(controlFD, uint32(queueIndex), queue); err != nil {
		return nil, fmt.Errorf("register virtqueue with index %d: %w", queueIndex, err)
	}
	return queue, nil
}

func (dev *Device) GetPacketForTx() (uint16, []byte, error) {
	idx, err := dev.TransmitQueue.TakeSingleIndex(context.TODO())
	if err != nil {
		return 0, nil, fmt.Errorf("transmit queue: %w", err)
	}
	buf := dev.TransmitQueue.GetDescriptorItem(idx)
	return idx, buf, nil
}

func (dev *Device) TransmitPacket(pkt *packet.OutPacket, kick bool) error {
	if len(pkt.SegmentIDs) == 0 {
		return nil
	}
	for idx := range pkt.SegmentIDs {
		segmentID := pkt.SegmentIDs[idx]
		dev.TransmitQueue.SetDescSize(segmentID, len(pkt.Segments[idx]))
	}
	err := dev.TransmitQueue.OfferDescriptorChains(pkt.SegmentIDs, false)
	if err != nil {
		return fmt.Errorf("offer descriptor chains: %w", err)
	}
	pkt.Reset()
	if kick {
		return dev.TransmitQueue.Kick()
	}

	return nil
}

func (dev *Device) TransmitPackets(pkts []*packet.OutPacket) error {
	if len(pkts) == 0 {
		return nil
	}

	for i := range pkts {
		if err := dev.TransmitPacket(pkts[i], false); err != nil {
			return err
		}
	}
	if err := dev.TransmitQueue.Kick(); err != nil {
		return err
	}
	return nil
}

// ProcessRxChain processes a single chain to create one packet. The number of processed chains is returned.
func (dev *Device) ProcessRxChain(pkt *VirtIOPacket, chain virtqueue.UsedElement) (int, error) {
	//read first element to see how many descriptors we need:
	pkt.Chain = uint16(chain.DescriptorIndex)
	buf := dev.ReceiveQueue.GetDescriptorItem(pkt.Chain)

	// The specification requires that the first descriptor chain starts
	// with a virtio-net header. It is not clear, whether it is also
	// required to be fully contained in the first buffer of that
	// descriptor chain, but it is reasonable to assume that this is
	// always the case.
	// The decode method already does the buffer length check.

	//HACK: we only want the last bit of the header, the NumBuffers field. So, let's grab just that:
	//numBuffers := binary.BigEndian.Uint16(buf[virtio.NetHdrSize-3:])
	//even bigger hack: apparently this is hitting some kind of memory access pitfall? Let's only grab the last byte:
	//numBuffers := buf[virtio.NetHdrSize-2]

	//if err = pkt.header.Decode(buf); err != nil {
	//	// The device misbehaved. There is no way we can gracefully
	//	// recover from this, because we don't know how many of the
	//	// following descriptor chains belong to this packet.
	//	return 0, fmt.Errorf("decode vnethdr: %w", err)
	//}

	//we have the header now: what do we need to do?
	//todo we're ignoring the header lol
	//if int(numBuffers) != 1 {
	//	return 0, fmt.Errorf("too smol-brain to handle more than one buffer per Chain item right now: %d chains, %d bufs", 1, int(numBuffers))
	//}

	if chain.Length > 16000 {
		//todo!
		pkt.payload = nil
		return 1, fmt.Errorf("too big packet length: %d", chain.Length)
	}

	//shift the buffer out of out:
	pkt.payload = buf[virtio.NetHdrSize:chain.Length]
	return 1, nil
}

type VirtIOPacket struct {
	payload []byte
	//header  virtio.NetHdr
	Chain uint16
}

func NewVIO() *VirtIOPacket {
	out := new(VirtIOPacket)
	out.payload = nil
	out.Chain = 0
	return out
}

func (v *VirtIOPacket) Reset() {
	v.payload = nil
	v.Chain = 0
}

func (v *VirtIOPacket) GetPayload() []byte {
	return v.payload //todo this could be dev.ReceiveQueue.GetDescriptorItem(idx)
}
func (v *VirtIOPacket) SetPayload(x []byte) {
	v.payload = x
}
