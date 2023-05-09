//go:build !mutex_debug
// +build !mutex_debug

package nebula

import (
	"sync"
)

type syncRWMutex = sync.RWMutex

func newSyncRWMutex(mutexKey) syncRWMutex {
	return sync.RWMutex{}
}

type mutexKey struct {
	Type    string
	SubType string
	ID      uint32
}
