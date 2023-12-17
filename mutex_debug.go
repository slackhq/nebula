//go:build mutex_debug
// +build mutex_debug

package nebula

import (
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
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

func alertMutex(err error) {
	log.Print(err, string(debug.Stack()))
}

func checkMutex(state map[mutexKey]mutexValue, add mutexKey) {
	for k := range state {
		if add == k {
			alertMutex(fmt.Errorf("re-entrant lock: state=%v add=%v", state, add))
		}
	}

	switch add.Type {
	case mutexKeyTypeHostInfo:
		// Check for any other hostinfo keys:
		for k := range state {
			if k.Type == mutexKeyTypeHostInfo {
				alertMutex(fmt.Errorf("grabbing hostinfo lock and already have a hostinfo lock: state=%v add=%v", state, add))
			}
		}
		if _, ok := state[mutexKey{Type: mutexKeyTypeHostMap}]; ok {
			alertMutex(fmt.Errorf("grabbing hostinfo lock and already have hostmap: state=%v add=%v", state, add))
		}
		if _, ok := state[mutexKey{Type: mutexKeyTypeHandshakeManager}]; ok {
			alertMutex(fmt.Errorf("grabbing hostinfo lock and already have handshake-manager: state=%v add=%v", state, add))
		}
		// case mutexKeyTypeHandshakeManager:
		// 	if _, ok := state[mutexKey{Type: mutexKeyTypeHostMap}]; ok {
		// 		alertMutex(fmt.Errorf("grabbing handshake-manager lock and already have hostmap: state=%v add=%v", state, add))
		// 	}
	case mutexKeyTypeHostMap:
		if _, ok := state[mutexKey{Type: mutexKeyTypeHandshakeManager}]; ok {
			alertMutex(fmt.Errorf("grabbing hostmap lock and already have handshake-manager: state=%v add=%v", state, add))
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
