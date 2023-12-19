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

// For each Key in this map, the Value is a list of lock types you can already have
// when you want to grab that Key. This ensures that locks are always fetched
// in the same order, to prevent deadlocks.
var allowedConcurrentLocks = map[mutexKeyType][]mutexKeyType{
	mutexKeyTypeHandshakeManager: {mutexKeyTypeHostMap},
}

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
	panic(err)
	// NOTE: you could switch to this log Line and remove the panic if you want
	// to log all failures instead of panicking on the first one
	//log.Print(err, string(debug.Stack()))
}

func checkMutex(state map[mutexKey]mutexValue, add mutexKey) {
	allowedConcurrent := allowedConcurrentLocks[add.Type]

	for k, v := range state {
		if add == k {
			alertMutex(fmt.Errorf("re-entrant lock: %s. previous allocation: %s", add, v))
		}

		// TODO use slices.Contains, but requires go1.21
		var found bool
		for _, a := range allowedConcurrent {
			if a == k.Type {
				found = true
				break
			}
		}
		if !found {
			alertMutex(fmt.Errorf("grabbing %s lock and already have these locks: %s", add.Type, state))
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
