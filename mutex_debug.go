//go:build mutex_debug
// +build mutex_debug

package nebula

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/timandy/routine"
)

var threadLocal routine.ThreadLocal = routine.NewThreadLocalWithInitial(func() any { return map[mutexKey]mutexValue{} })

type mutexKey struct {
	Type    string
	SubType string
	ID      uint32
}

type mutexValue struct {
	file string
	line int
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

func checkMutex(state map[mutexKey]mutexValue, add mutexKey) {
	switch add.Type {
	case "hostinfo":
		// Check for any other hostinfo keys:
		for k := range state {
			if k.Type == "hostinfo" {
				panic(fmt.Errorf("grabbing hostinfo lock and already have a hostinfo lock: state=%v add=%v", state, add))
			}
		}
		if _, ok := state[mutexKey{Type: "hostmap", SubType: "main"}]; ok {
			panic(fmt.Errorf("grabbing hostinfo lock and already have hostmap-main: state=%v add=%v", state, add))
		}
		if _, ok := state[mutexKey{Type: "hostmap", SubType: "pending"}]; ok {
			panic(fmt.Errorf("grabbing hostinfo lock and already have hostmap-pending: state=%v add=%v", state, add))
		}
	case "hostmap-pending":
		if _, ok := state[mutexKey{Type: "hostmap", SubType: "main"}]; ok {
			panic(fmt.Errorf("grabbing hostmap-pending lock and already have hostmap-main: state=%v add=%v", state, add))
		}
	}
}

func (s *syncRWMutex) Lock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	checkMutex(m, s.mutexKey)
	v := mutexValue{}
	_, v.file, v.line, _ = runtime.Caller(1)
	m[s.mutexKey] = v
	s.RWMutex.Lock()
}

func (s *syncRWMutex) Unlock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	delete(m, s.mutexKey)
	s.RWMutex.Unlock()
}

func (s *syncRWMutex) RLock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	checkMutex(m, s.mutexKey)
	v := mutexValue{}
	_, v.file, v.line, _ = runtime.Caller(1)
	m[s.mutexKey] = v
	s.RWMutex.RLock()
}

func (s *syncRWMutex) RUnlock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	delete(m, s.mutexKey)
	s.RWMutex.RUnlock()
}
