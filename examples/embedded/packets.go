package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func UDPPacket(from net.IP, toIp net.IP, toPort uint16, fromPort uint16, data []byte) []byte {
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    from,
		DstIP:    toIp,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(fromPort),
		DstPort: layers.UDPPort(toPort),
	}
	err := udp.SetNetworkLayerForChecksum(&ip)
	if err != nil {
		panic(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buffer, opt, &ip, &udp, gopacket.Payload(data))
	if err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

func DecodePacket(myPacketData []byte) {
	packet := gopacket.NewPacket(myPacketData, layers.LayerTypeIPv4, gopacket.Lazy)
	v4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if v4 == nil {
		fmt.Println("No ipv4 data found")
		return
	}
	fmt.Printf("From src %v to dst %v\n", v4.SrcIP, v4.DstIP)
	tV := packet.Layer(layers.LayerTypeUDP)
	if tV == nil {
		fmt.Println("No udp layer found")
		return
	}
	udp := tV.(*layers.UDP)
	if udp == nil {
		fmt.Println("No udp data found")
		return
	}

	fmt.Printf("From src port %d to dst port %d\n", uint16(udp.SrcPort), uint16(udp.DstPort))

	data := packet.ApplicationLayer()
	if data == nil {
		fmt.Println("No application data found")
		return
	}
	fmt.Println("App Payload: ", data.Payload())
}
