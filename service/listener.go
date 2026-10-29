package service

import (
	"net"
	"sync"
)

type tcpListener struct {
	s      *Service
	addr   *net.TCPAddr
	keys   []listenerKey
	accept chan net.Conn

	// closed is closed instead of accept so a handler blocked handing off a
	// connection can't send on a closed channel.
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *tcpListener) Accept() (net.Conn, error) {
	// select picks randomly among ready cases, so without this a handler still
	// waiting to hand off could win over closed after Close has returned.
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *tcpListener) Close() error {
	l.closeOnce.Do(func() {
		// Close before leaving the map so a concurrent closeListeners that
		// no longer sees this listener knows Accept is already released.
		close(l.closed)

		// Keys are only reusable once removed here, so this listener still owns
		// every one of them.
		l.s.mu.Lock()
		for _, key := range l.keys {
			delete(l.s.mu.listeners, key)
		}
		l.s.mu.Unlock()
	})
	return nil
}

// Addr returns the listener's network address.
func (l *tcpListener) Addr() net.Addr {
	return l.addr
}
