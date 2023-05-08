//go:build mutex_debug
// +build mutex_debug

package nebula

import (
	"strings"
	"sync"

	"github.com/timandy/routine"
)

var threadLocal routine.ThreadLocal = routine.NewThreadLocalWithInitial(func() any { return map[string]bool{} })

type syncRWMutex struct {
	sync.RWMutex
	mutexType string
}

func newSyncRWMutex(t ...string) syncRWMutex {
	return syncRWMutex{
		mutexType: strings.Join(t, "-"),
	}
}

func checkMutex(state map[string]bool, add string) {
	if add == "hostinfo" {
		if state["hostmap-main"] {
			panic("grabbing hostinfo lock and already have hostmap-main")
		}
		if state["hostmap-pending"] {
			panic("grabbing hostinfo lock and already have hostmap-pending")
		}
	}
	if add == "hostmap-pending" {
		if state["hostmap-main"] {
			panic("grabbing hostmap-pending lock and already have hostmap-main")
		}
	}
}

func (s *syncRWMutex) Lock() {
	m := threadLocal.Get().(map[string]bool)
	checkMutex(m, s.mutexType)
	m[s.mutexType] = true
	s.RWMutex.Lock()
}

func (s *syncRWMutex) Unlock() {
	m := threadLocal.Get().(map[string]bool)
	m[s.mutexType] = false
	s.RWMutex.Unlock()
}

func (s *syncRWMutex) RLock() {
	m := threadLocal.Get().(map[string]bool)
	checkMutex(m, s.mutexType)
	m[s.mutexType] = true
	s.RWMutex.RLock()
}

func (s *syncRWMutex) RUnlock() {
	m := threadLocal.Get().(map[string]bool)
	m[s.mutexType] = false
	s.RWMutex.RUnlock()
}
