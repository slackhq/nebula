package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// P is the export required by the nebula plugin interface.
var P = Echo{}

// Echo provides the implementation of a Nebula Message Plugin interface that will echo
// a payload to a remote nebula nodes log.
type Echo struct {
	dest    uint32
	payload string
	period  time.Duration
}

// Name returns the name of this plugin.
func (e *Echo) Name() string {
	return "echo"
}

// Configure accpets a config map that will be used to define the behaviour of the plugin.
func (e *Echo) Configure(config map[interface{}]interface{}) error {
	var (
		dest    uint32
		payload string
		period  time.Duration
	)
	for k, v := range config {
		switch fmt.Sprint(k) {
		case "dest":
			dest = ip2int(net.ParseIP(fmt.Sprint(v)))
		case "payload":
			payload = fmt.Sprint(v)
		case "period":
			d, err := time.ParseDuration(fmt.Sprint(v))
			if err != nil {
				return fmt.Errorf("invalid duration in config.period")
			}
			period = d
		}
	}
	if dest == 0 || payload == "" {
		return fmt.Errorf("dest and payload must be specified if using config")
	}
	if period == 0 {
		period = 5 * time.Second
	}

	e.dest = dest
	e.payload = payload
	e.period = period

	return nil
}

// Receive accepts the bytes of a packet, discards the IPv4 header bytes
// then prints the resultant payload to stdout as a string.
func (e *Echo) Receive(b []byte) error {
	if len(b) < 20 {
		return fmt.Errorf("expect more than 20 bytes, got %d", len(b))
	}

	_, err := fmt.Println(string(b[20:]))
	return err
}

// Run is the function that is called by Nebula to indicate that the plugin can start sending
// traffic using the send function that is passed in.
func (e *Echo) Run(send func(ip uint32, payload []byte)) {
	if e.period == 0 || e.dest == 0 || e.payload == "" {
		return
	}

	for range time.Tick(e.period) {
		send(e.dest, []byte(e.payload))
	}

	return
}

func ip2int(ip []byte) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
