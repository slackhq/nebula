package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
)

func main() {
	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	configTest := flag.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printUsage := flag.Bool("help", false, "Print command line usage")
	thisIP := flag.String("thisIP", "10.0.0.3", "This node's IP in the nebula network")
	thisPort := flag.Uint64("thisPort", 8080, "Port this node will use for packets")
	targetIP := flag.String("targetIP", "10.0.0.4", "Target node's IP in the nebula network")
	targetPort := flag.Uint64("targetPort", 8080, "Port the target node will use for packets")

	flag.Parse()

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout

	config := nebula.NewConfig(l)
	err := config.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}
	cs, err := nebula.NewCertStateFromConfig(config)
	if err != nil {
		fmt.Printf("failed to load cert from config: %s", err)
		os.Exit(1)
	}

	rxChan := make(chan []byte, 500)
	txChan := make(chan []byte, 500)

	ft := nebula.NewFakeTun("fakeTun", cs.GetCIDR(), txChan, rxChan)

	go occasionalInjector(txChan, net.ParseIP(*thisIP), net.ParseIP(*targetIP), *thisPort, *targetPort)
	go receiverHandler(rxChan)

	c, err := nebula.MainWithProvidedTUN(config, *configTest, "a", l, nil, ft)

	switch v := err.(type) {
	case nebula.ContextualError:
		v.Log(l)
		os.Exit(1)
	case error:
		l.WithError(err).Error("Failed to start")
		os.Exit(1)
	}

	if !*configTest {
		c.Start()
		c.ShutdownBlock()
	}

	os.Exit(0)
}

func occasionalInjector(sendPackets chan<- []byte, usIP, themIP net.IP, usPort, themPort uint64) {
	payload := []byte{0x0, 0x1, 0x2, 0x3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	for {
		time.Sleep(time.Second)
		fmt.Printf("Injecting packet from %v:%v to %v:%v\n", usIP.To4(), usPort, themIP.To4(), themPort)
		b := UDPPacket(usIP, themIP, uint16(themPort), uint16(usPort), payload)
		DecodePacket(b)
		sendPackets <- b

		for i := 0; i < len(payload); i++ {
			if payload[i] == 0xff {
				payload[i] = 0
			} else {
				payload[i] += 1
			}
		}
	}
}

func receiverHandler(receivePackets <-chan []byte) {
	for {
		b := <-receivePackets
		DecodePacket(b)
	}
}
