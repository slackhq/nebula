package nebula

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/noiseutil"
)

const (
	// queueContentionUpgrade is how many times a tunnel's writeLock must be found held within
	// queueContentionWindow before the tunnel builds per routine send ciphers. A busy tunnel gets there in a few
	// milliseconds, an idle or lightly used one never does and keeps its one cipher.
	queueContentionUpgrade = 64
	// queueContentionWindow is how recent those contentions must be, an older count starts over
	queueContentionWindow = 100 * time.Millisecond
)

// lazyQueueKeys builds a tunnel's per routine send ciphers the first time its writeLock is contended enough
type lazyQueueKeys struct {
	// n is the number of queues
	n int
	// sendKey and cipher build the extra ciphers, dropped once they are built
	sendKey *noise.CipherState
	cipher  noise.CipherFunc

	contended atomic.Uint32
	// windowStart is when the current count of contentions started, in UnixNano
	windowStart atomic.Int64
	// built is set by the one caller that builds the ciphers
	built atomic.Bool
}

// queueKey is one of a tunnel's per routine send ciphers and the lock serializing its encryptions
type queueKey struct {
	mu  sync.Mutex
	key noiseutil.CipherState
	// Keep each routine's lock on its own cache line
	_ [64 - 8 - 16]byte
}

// newQueueKeys builds n send ciphers from sendKey, nil if the cipher can't be built that way.
//
// A cipher that needs writeLock (FIPS 140, boringcrypto) refuses a nonce that is not strictly increasing. Every
// routine reserves its counters from the shared messageCounter under its own cipher's lock, so the counters each
// cipher sees still strictly increase, and every counter is used once across all of them. That holds across the
// switch too: a sender that picked eKey before the new ciphers existed keeps using it under writeLock, and a new
// cipher only sees counters reserved after it was built.
func newQueueKeys(sendKey *noise.CipherState, cipher noise.CipherFunc, n int) []queueKey {
	k := sendKey.UnsafeKey()
	keys := make([]queueKey, n)
	for i := range keys {
		cs, ok := cipher.Cipher(k).(noiseutil.CipherState)
		if !ok {
			return nil
		}
		keys[i].key = cs
	}
	return keys
}

// lockEncrypter returns the cipher queue q sends with. When noiseutil.EncryptLockNeeded it also locks and returns
// the lock to hold around reserving a counter and encrypting, unlock it when done; otherwise lock is nil.
//
// That is the tunnel's eKey and writeLock until writeLock has been found held queueContentionUpgrade times, then
// queue q's own cipher. Each queue gets its own, queue 0 too, so no queue's lock shares a cache line with the
// counter every queue updates.
func (cs *ConnectionState) lockEncrypter(q int) (key noiseutil.CipherState, lock *sync.Mutex) {
	if !noiseutil.EncryptLockNeeded {
		return cs.eKey, nil
	}

	if keys := cs.queueKeys.Load(); keys != nil {
		k := &(*keys)[q%len(*keys)]
		k.mu.Lock()
		return k.key, &k.mu
	}

	if cs.lazyQueues == nil {
		// Never builds per routine ciphers, nothing to count
		cs.writeLock.Lock()
		return cs.eKey, &cs.writeLock
	}

	if !cs.writeLock.TryLock() {
		cs.noteContention()
		cs.writeLock.Lock()
	}
	return cs.eKey, &cs.writeLock
}

// noteContention counts writeLock being found held, and builds the per routine ciphers once the count reaches
// queueContentionUpgrade within queueContentionWindow. They are built once, by the caller that wins built.
func (cs *ConnectionState) noteContention() {
	lq := cs.lazyQueues
	if lq == nil || lq.built.Load() {
		return
	}

	// Start the count over when it is too old. A racing reset or two only shifts the window a little.
	now := time.Now().UnixNano()
	if start := lq.windowStart.Load(); now-start > int64(queueContentionWindow) && lq.windowStart.CompareAndSwap(start, now) {
		lq.contended.Store(0)
	}
	if lq.contended.Add(1) < queueContentionUpgrade || !lq.built.CompareAndSwap(false, true) {
		return
	}
	keys := newQueueKeys(lq.sendKey, lq.cipher, lq.n)
	// Only this caller ever reads sendKey, drop our reference to the key
	lq.sendKey = nil
	if keys != nil {
		cs.queueKeys.Store(&keys)
	}
}
