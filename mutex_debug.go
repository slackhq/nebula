//go:build mutex_debug
// +build mutex_debug

package nebula

import (
	"fmt"
	"sync"

	"github.com/timandy/routine"
)

var threadLocal routine.ThreadLocal = routine.NewThreadLocalWithInitial(func() any { return map[mutexKey]bool{} })

type mutexKey struct {
	Type    string
	SubType string
	ID      uint32
}

type syncRWMutex struct {
	sync.RWMutex
	mutexKey
}

func newSyncRWMutex(key mutexKey) syncRWMutex {
	return syncRWMutex{
		mutexKey: key,
	}
}

func checkMutex(state map[mutexKey]bool, add mutexKey) {
	switch add.Type {
	case "hostinfo":
		// Check for any other hostinfo keys:
		for k, v := range state {
			if k.Type == "hostinfo" && v {
				panic(fmt.Errorf("grabbing hostinfo lock and already have a hostinfo lock: state=%v add=%v", state, add))
			}
		}
		if state[mutexKey{Type: "hostmap", SubType: "main"}] {
			panic(fmt.Errorf("grabbing hostinfo lock and already have hostmap-main: state=%v add=%v", state, add))
		}
		if state[mutexKey{Type: "hostmap", SubType: "pending"}] {
			panic(fmt.Errorf("grabbing hostinfo lock and already have hostmap-pending: state=%v add=%v", state, add))
		}
	case "hostmap-pending":
		if state[mutexKey{Type: "hostmap", SubType: "main"}] {
			panic(fmt.Errorf("grabbing hostmap-pending lock and already have hostmap-main: state=%v add=%v", state, add))
		}
	}
}

func (s *syncRWMutex) Lock() {
	m := threadLocal.Get().(map[mutexKey]bool)
	checkMutex(m, s.mutexKey)
	m[s.mutexKey] = true
	s.RWMutex.Lock()
}

func (s *syncRWMutex) Unlock() {
	m := threadLocal.Get().(map[mutexKey]bool)
	delete(m, s.mutexKey)
	s.RWMutex.Unlock()
}

func (s *syncRWMutex) RLock() {
	m := threadLocal.Get().(map[mutexKey]bool)
	checkMutex(m, s.mutexKey)
	m[s.mutexKey] = true
	s.RWMutex.RLock()
}

func (s *syncRWMutex) RUnlock() {
	m := threadLocal.Get().(map[mutexKey]bool)
	delete(m, s.mutexKey)
	s.RWMutex.RUnlock()
}
