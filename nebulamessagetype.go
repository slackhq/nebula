package nebula

import "strings"

//go:generate go build -o build/tools/stringer golang.org/x/tools/cmd/stringer
//go:generate ./build/tools/stringer -type NebulaMessageType,NebulaMessageSubType

type NebulaMessageType uint8
type NebulaMessageSubType uint8

const (
	handshake NebulaMessageType = iota
	message
	recvError
	lightHouse
	test
	closeTunnel
	_ // DEPRECATED(testRemote)
	_ // DEPRECATED(testRemoteReply)

)

const (
	testRequest NebulaMessageSubType = iota
	testReply

	handshakeIXPSK0 NebulaMessageSubType = iota
	handshakeXXPSK0
)

var subTypeMap = map[NebulaMessageType]*map[NebulaMessageSubType]bool{
	handshake: {
		handshakeIXPSK0: true,
	},
	message:    {},
	recvError:  {},
	lightHouse: {},
	test: {
		testRequest: true,
		testReply:   true,
	},
	closeTunnel: {},
}

// TypeName will transform a nebula message type into a human string
func TypeName(t NebulaMessageType) string {
	return strings.Replace(t.String(), "NebulaMessageType", "unknown", 1)
}

// SubTypeName will transform a nebula message sub type into a human string
func SubTypeName(t NebulaMessageType, s NebulaMessageSubType) string {
	n, ok := subTypeMap[t]
	if ok {
		if (*n)[s] {
			return s.String()
		}

		if s == 0 {
			return "none"
		}
	}

	return "unknown"
}
