package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// UDP_SEGMENT enables GSO segmentation
	UDP_SEGMENT = 103
	// Maximum GSO segment size (typical MTU - headers)
	maxGSOSize = 1400
)

func main() {
	destAddr := flag.String("dest", "10.4.0.16:4202", "Destination address")
	gsoSize := flag.Int("gso", 1400, "GSO segment size")
	totalSize := flag.Int("size", 14000, "Total payload size to send")
	count := flag.Int("count", 1, "Number of packets to send")
	flag.Parse()

	if *gsoSize > maxGSOSize {
		log.Fatalf("GSO size %d exceeds maximum %d", *gsoSize, maxGSOSize)
	}

	// Resolve destination address
	_, err := net.ResolveUDPAddr("udp", *destAddr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	// Create a raw UDP socket with GSO support
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer unix.Close(fd)

	// Bind to a local address
	localAddr := &unix.SockaddrInet4{
		Port: 0, // Let the system choose a port
	}
	if err := unix.Bind(fd, localAddr); err != nil {
		log.Fatalf("Failed to bind socket: %v", err)
	}

	fmt.Printf("Sending UDP packets with GSO enabled\n")
	fmt.Printf("Destination: %s\n", *destAddr)
	fmt.Printf("GSO segment size: %d bytes\n", *gsoSize)
	fmt.Printf("Total payload size: %d bytes\n", *totalSize)
	fmt.Printf("Number of packets: %d\n\n", *count)

	// Create payload
	payload := make([]byte, *totalSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	dest := netip.MustParseAddrPort(*destAddr)

	//if err := unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_SEGMENT, 1400); err != nil {
	//	panic(err)
	//}

	for i := 0; i < *count; i++ {
		err := WriteBatch(fd, payload, dest, uint16(*gsoSize), true)
		if err != nil {
			log.Printf("Send error on packet %d: %v", i, err)
			continue
		}

		if (i+1)%100 == 0 || i == *count-1 {
			fmt.Printf("Sent %d packets\n", i+1)
		}
	}
	fmt.Printf("now, let's send without the correct ctrl header\n")
	time.Sleep(time.Second)
	for i := 0; i < *count; i++ {
		err := WriteBatch(fd, payload, dest, uint16(*gsoSize), false)
		if err != nil {
			log.Printf("Send error on packet %d: %v", i, err)
			continue
		}

		if (i+1)%100 == 0 || i == *count-1 {
			fmt.Printf("Sent %d packets\n", i+1)
		}
	}

}

func WriteBatch(fd int, payload []byte, addr netip.AddrPort, segSize uint16, withHeader bool) error {
	msgs := make([]rawMessage, 0, 1)
	iovs := make([]iovec, 0, 1)
	names := make([][unix.SizeofSockaddrInet6]byte, 0, 1)

	sent := 0

	pkts := []BatchPacket{
		{
			Payload: payload,
			Addr:    addr,
		},
	}

	for _, pkt := range pkts {
		if len(pkt.Payload) == 0 {
			sent++
			continue
		}

		msgs = append(msgs, rawMessage{})
		iovs = append(iovs, iovec{})
		names = append(names, [unix.SizeofSockaddrInet6]byte{})

		idx := len(msgs) - 1
		msg := &msgs[idx]
		iov := &iovs[idx]
		name := &names[idx]

		setIovecSlice(iov, pkt.Payload)
		msg.Hdr.Iov = iov
		msg.Hdr.Iovlen = 1

		if withHeader {
			setRawMessageControl(msg, buildGSOControlMessage(segSize)) //
		} else {
			setRawMessageControl(msg, nil) //
		}

		msg.Hdr.Flags = 0

		nameLen, err := encodeSockaddr(name[:], pkt.Addr)
		if err != nil {
			return err
		}
		msg.Hdr.Name = &name[0]
		msg.Hdr.Namelen = nameLen
	}

	if len(msgs) == 0 {
		return errors.New("nothing to write")
	}

	offset := 0
	for offset < len(msgs) {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			uintptr(fd),
			uintptr(unsafe.Pointer(&msgs[offset])),
			uintptr(len(msgs)-offset),
			0,
			0,
			0,
		)

		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return &net.OpError{Op: "sendmmsg", Err: errno}
		}

		if n == 0 {
			break
		}
		offset += int(n)
	}

	return nil
}

func buildGSOControlMessage(segSize uint16) []byte {
	control := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	setCmsgLen(hdr, unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):unix.CmsgLen(0)+2], uint16(segSize))

	return control
}
