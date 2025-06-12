//go:build !mutex_debug
// +build !mutex_debug

package nebula

import (
	"sync"
)

type mutexKey = string
type syncRWMutex = sync.RWMutex
type syncMutex = sync.Mutex

func newSyncRWMutex(mutexKey) syncRWMutex {
	return sync.RWMutex{}
}

func newSyncMutex(mutexKey) syncMutex {
	return sync.Mutex{}
}

func chanDebugRecv(key mutexKey) {}
func chanDebugSend(key mutexKey) {}
