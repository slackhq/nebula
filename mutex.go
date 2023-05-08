//go:build !mutex_debug
// +build !mutex_debug

package nebula

import (
	"sync"
)

type syncRWMutex = sync.RWMutex

func newSyncRWMutex(t ...string) syncRWMutex {
	return sync.RWMutex{}
}
