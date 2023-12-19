//go:build mutex_debug
// +build mutex_debug

package nebula

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/heimdalr/dag"
	"github.com/timandy/routine"
)

var threadLocal routine.ThreadLocal = routine.NewThreadLocalWithInitial(func() any { return map[mutexKey]mutexValue{} })

var allowedDAG *dag.DAG

func init() {
	allowedDAG = dag.NewDAG()
	for k, v := range allowedConcurrentLocks {
		allowedDAG.AddVertexByID(string(k), k)
		for _, t := range v {
			if _, err := allowedDAG.GetVertex(string(t)); err != nil {
				allowedDAG.AddVertexByID(string(t), t)
			}
		}
	}
	for k, v := range allowedConcurrentLocks {
		for _, t := range v {
			allowedDAG.AddEdge(string(t), string(k))
		}
	}

	for k := range allowedConcurrentLocks {
		anc, err := allowedDAG.GetAncestors(string(k))
		if err != nil {
			panic(err)
		}

		var allowed []mutexKeyType
		for t := range anc {
			allowed = append(allowed, mutexKeyType(t))
		}
		allowedConcurrentLocks[k] = allowed
	}
}

type syncRWMutex struct {
	sync.RWMutex
	mutexKey
}

type syncMutex struct {
	sync.Mutex
	mutexKey
}

func newSyncRWMutex(key mutexKey) syncRWMutex {
	return syncRWMutex{
		mutexKey: key,
	}
}

func newSyncMutex(key mutexKey) syncMutex {
	return syncMutex{
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

func (s *syncMutex) Lock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	checkMutex(m, s.mutexKey)
	v := mutexValue{}
	_, v.file, v.line, _ = runtime.Caller(1)
	m[s.mutexKey] = v
	s.Mutex.Lock()
}

func (s *syncMutex) Unlock() {
	m := threadLocal.Get().(map[mutexKey]mutexValue)
	delete(m, s.mutexKey)
	s.Mutex.Unlock()
}
