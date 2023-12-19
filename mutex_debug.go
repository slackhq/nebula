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

type mutexKey = string

// For each Key in this map, the Value is a list of lock types you can already have
// when you want to grab that Key. This ensures that locks are always fetched
// in the same order, to prevent deadlocks.
var allowedConcurrentLocks = map[mutexKey][]mutexKey{
	"connection-manager-in":         {"hostmap"},
	"connection-manager-out":        {"connection-state-write", "connection-manager-in"},
	"connection-manager-relay-used": {"handshake-hostinfo"},
	"connection-state-write":        {"hostmap"},
	"firewall-conntrack":            {"handshake-hostinfo"},
	"handshake-manager":             {"hostmap"},
	"hostmap":                       {"handshake-hostinfo"},
	"lighthouse":                    {"handshake-manager"},
	"relay-state":                   {"hostmap", "connection-manager-relay-used"},
	"remote-list":                   {"lighthouse"},
}

type mutexValue struct {
	file string
	line int
}

func (m mutexValue) String() string {
	return fmt.Sprintf("%s:%d", m.file, m.line)
}

var threadLocal routine.ThreadLocal = routine.NewThreadLocalWithInitial(func() any { return map[mutexKey]mutexValue{} })

var allowedDAG *dag.DAG

// We build a directed acyclic graph to assert that the locks can only be
// acquired in a determined order, If there are cycles in the DAG, then we
// know that the locking order is not guaranteed.
func init() {
	allowedDAG = dag.NewDAG()
	for k, v := range allowedConcurrentLocks {
		_ = allowedDAG.AddVertexByID(k, k)
		for _, t := range v {
			_ = allowedDAG.AddVertexByID(t, t)
		}
	}
	for k, v := range allowedConcurrentLocks {
		for _, t := range v {
			if err := allowedDAG.AddEdge(t, k); err != nil {
				panic(fmt.Errorf("Failed to assembled DAG for allowedConcurrentLocks: %w", err))
			}
		}
	}

	// Rebuild allowedConcurrentLocks as a flattened list of all possibilities
	for k := range allowedConcurrentLocks {
		anc, err := allowedDAG.GetAncestors(k)
		if err != nil {
			panic(err)
		}

		var allowed []mutexKey
		for t := range anc {
			allowed = append(allowed, mutexKey(t))
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
	allowedConcurrent := allowedConcurrentLocks[add]

	for k, v := range state {
		if add == k {
			alertMutex(fmt.Errorf("re-entrant lock: %s. previous allocation: %s", add, v))
		}

		// TODO use slices.Contains, but requires go1.21
		var found bool
		for _, a := range allowedConcurrent {
			if a == k {
				found = true
				break
			}
		}
		if !found {
			alertMutex(fmt.Errorf("grabbing %s lock and already have these locks: %s", add, state))
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
