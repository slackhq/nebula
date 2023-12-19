package nebula

import "fmt"

type mutexKeyType string

const (
	mutexKeyTypeHostMap mutexKeyType = "hostmap"

	mutexKeyTypeLightHouse           = "lighthouse"
	mutexKeyTypeRemoteList           = "remote-list"
	mutexKeyTypeFirewallConntrack    = "firewall-conntrack"
	mutexKeyTypeHostInfo             = "hostinfo"
	mutexKeyTypeRelayState           = "relay-state"
	mutexKeyTypeHandshakeHostInfo    = "handshake-hostinfo"
	mutexKeyTypeHandshakeManager     = "handshake-manager"
	mutexKeyTypeConnectionStateWrite = "connection-state-write-lock"

	mutexKeyTypeConnectionManagerIn        = "connection-manager-in-lock"
	mutexKeyTypeConnectionManagerOut       = "connection-manager-out-lock"
	mutexKeyTypeConnectionManagerRelayUsed = "connection-manager-relay-used-lock"
)

// For each Key in this map, the Value is a list of lock types you can already have
// when you want to grab that Key. This ensures that locks are always fetched
// in the same order, to prevent deadlocks.
var allowedConcurrentLocks = map[mutexKeyType][]mutexKeyType{
	mutexKeyTypeHostMap:           {mutexKeyTypeHandshakeHostInfo},
	mutexKeyTypeFirewallConntrack: {mutexKeyTypeHandshakeHostInfo},

	mutexKeyTypeHandshakeManager:     {mutexKeyTypeHostMap},
	mutexKeyTypeConnectionStateWrite: {mutexKeyTypeHostMap},

	mutexKeyTypeLightHouse: {mutexKeyTypeHandshakeManager},
	mutexKeyTypeRemoteList: {mutexKeyTypeLightHouse},

	mutexKeyTypeConnectionManagerIn:        {mutexKeyTypeHostMap},
	mutexKeyTypeConnectionManagerOut:       {mutexKeyTypeConnectionStateWrite, mutexKeyTypeConnectionManagerIn},
	mutexKeyTypeConnectionManagerRelayUsed: {mutexKeyTypeHandshakeHostInfo},

	mutexKeyTypeRelayState: {mutexKeyTypeHostMap, mutexKeyTypeConnectionManagerRelayUsed},
}

type mutexKey struct {
	Type mutexKeyType
	ID   uint32
}

type mutexValue struct {
	file string
	line int
}

func (m mutexKey) String() string {
	if m.ID == 0 {
		return fmt.Sprintf("%s", m.Type)
	} else {
		return fmt.Sprintf("%s(%d)", m.Type, m.ID)
	}
}

func (m mutexValue) String() string {
	return fmt.Sprintf("%s:%d", m.file, m.line)
}
