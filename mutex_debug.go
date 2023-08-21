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

type mutexKeyType string

const (
	mutexKeyTypeHostMap          mutexKeyType = "hostmap"
	mutexKeyTypeHostInfo                      = "hostinfo"
	mutexKeyTypeHandshakeManager              = "handshake-manager"
)

type mutexKey struct {
	Type mutexKeyType
	ID   uint32
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
	case mutexKeyTypeHostInfo:
		// Check for any other hostinfo keys:
		for k := range state {
			if k.Type == mutexKeyTypeHostInfo {
				panic(fmt.Errorf("grabbing hostinfo lock and already have a hostinfo lock: state=%v add=%v", state, add))
			}
		}
		if _, ok := state[mutexKey{Type: mutexKeyTypeHostMap}]; ok {
			panic(fmt.Errorf("grabbing hostinfo lock and already have hostmap: state=%v add=%v", state, add))
		}
		if _, ok := state[mutexKey{Type: mutexKeyTypeHandshakeManager}]; ok {
			panic(fmt.Errorf("grabbing hostinfo lock and already have handshake-manager: state=%v add=%v", state, add))
		}
	case mutexKeyTypeHandshakeManager:
		if _, ok := state[mutexKey{Type: mutexKeyTypeHostMap}]; ok {
			panic(fmt.Errorf("grabbing handshake-manager lock and already have hostmap: state=%v add=%v", state, add))
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
