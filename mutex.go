//go:build !mutex_debug
// +build !mutex_debug

package nebula

import (
	"sync"
)

type syncRWMutex = sync.RWMutex

type mutexKeyType string

const (
	mutexKeyTypeHostMap          mutexKeyType = "hostmap"
	mutexKeyTypeHostInfo                      = "hostinfo"
	mutexKeyTypeHandshakeManager              = "handshake-manager"
)

func newSyncRWMutex(mutexKey) syncRWMutex {
	return sync.RWMutex{}
}

type mutexKey struct {
	Type mutexKeyType
	ID   uint32
}
