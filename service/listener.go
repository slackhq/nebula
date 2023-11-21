package service

import (
	"io"
	"net"
)

type tcpListener struct {
	port   uint16
	s      *Service
	addr   *net.TCPAddr
	accept chan net.Conn
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, ok := <-l.accept
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (l *tcpListener) Close() error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	delete(l.s.mu.listeners, uint16(l.addr.Port))

	close(l.accept)

	return nil
}

// Addr returns the listener's network address.
func (l *tcpListener) Addr() net.Addr {
	return l.addr
}
