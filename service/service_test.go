package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/overlay"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sync/errgroup"
)

type m = map[string]any

func newSimpleService(caCrt cert.Certificate, caKey []byte, name string, udpIp netip.Addr, overrides m) *Service {
	_, _, myPrivKey, myPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, caCrt, caKey, "a", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.PrefixFrom(udpIp, 24)}, nil, []string{})
	caB, err := caCrt.MarshalPEM()
	if err != nil {
		panic(err)
	}

	mc := m{
		"pki": m{
			"ca":   string(caB),
			"cert": string(myPEM),
			"key":  string(myPrivKey),
		},
		//"tun": m{"disabled": true},
		"firewall": m{
			"outbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
			"inbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
		},
		"timers": m{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
		"handshakes": m{
			"try_interval": "200ms",
		},
	}

	if overrides != nil {
		err = mergo.Merge(&overrides, mc, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		mc = overrides
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	var c config.C
	if err := c.LoadString(string(cb)); err != nil {
		panic(err)
	}

	logger := logging.NewLogger(os.Stdout)

	control, err := nebula.Main(&c, false, "custom-app", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		panic(err)
	}

	s, err := New(control)
	if err != nil {
		panic(err)
	}
	return s
}

// ephemeralUDPPort reserves a free UDP port by binding port 0, then releases
// it for the caller to use. A fixed port would collide with concurrent test
// runs or an unrelated process (say, a real nebula) already listening on it.
func ephemeralUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

func TestService(t *testing.T) {
	lighthousePort := ephemeralUDPPort(t)

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	a := newSimpleService(ca, caKey, "a", netip.MustParseAddr("10.0.0.1"), m{
		"static_host_map": m{},
		"lighthouse": m{
			"am_lighthouse": true,
		},
		"listen": m{
			"host": "0.0.0.0",
			"port": lighthousePort,
		},
	})
	b := newSimpleService(ca, caKey, "b", netip.MustParseAddr("10.0.0.2"), m{
		"static_host_map": m{
			"10.0.0.1": []string{fmt.Sprintf("localhost:%d", lighthousePort)},
		},
		"lighthouse": m{
			"hosts":    []string{"10.0.0.1"},
			"interval": 1,
		},
	})

	ln, err := a.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	var eg errgroup.Group
	eg.Go(func() error {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		t.Log("accepted connection")

		if _, err := conn.Write([]byte("server msg")); err != nil {
			return err
		}

		t.Log("server: wrote message")

		data := make([]byte, 100)
		n, err := conn.Read(data)
		if err != nil {
			return err
		}
		data = data[:n]
		if !bytes.Equal(data, []byte("client msg")) {
			return errors.New("got invalid message from client")
		}
		t.Log("server: read message")
		return conn.Close()
	})

	c, err := b.DialContext(context.Background(), "tcp", "10.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("client msg")); err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 100)
	n, err := c.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	data = data[:n]
	if !bytes.Equal(data, []byte("server msg")) {
		t.Fatal("got invalid message from client")
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	if err := eg.Wait(); err != nil {
		t.Fatal(err)
	}
}

// A listener that is never accepted from must not stall connections to other
// ports, and closing it must not block.
func TestServiceUnacceptedListener(t *testing.T) {
	lighthousePort := ephemeralUDPPort(t)

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	a := newSimpleService(ca, caKey, "a", netip.MustParseAddr("10.0.0.1"), m{
		"static_host_map": m{},
		"lighthouse": m{
			"am_lighthouse": true,
		},
		"listen": m{
			"host": "0.0.0.0",
			"port": lighthousePort,
		},
	})
	t.Cleanup(func() { _ = a.Close() })
	b := newSimpleService(ca, caKey, "b", netip.MustParseAddr("10.0.0.2"), m{
		"static_host_map": m{
			"10.0.0.1": []string{fmt.Sprintf("127.0.0.1:%d", lighthousePort)},
		},
		"lighthouse": m{
			"hosts":    []string{"10.0.0.1"},
			"interval": 1,
		},
	})
	t.Cleanup(func() { _ = b.Close() })

	idle, err := a.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	active, err := a.Listen("tcp", ":1235")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	idleConn, err := b.DialContext(ctx, "tcp", "10.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer idleConn.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := active.Accept()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	activeConn, err := b.DialContext(ctx, "tcp", "10.0.0.1:1235")
	if err != nil {
		t.Fatalf("dial to accepted port stalled behind idle listener: %v", err)
	}
	defer activeConn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accept stalled behind idle listener")
	}

	closed := make(chan error, 1)
	go func() { closed <- idle.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing idle listener blocked")
	}

	if _, err := idle.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed from closed listener, got %v", err)
	}
	if err := idle.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// Accept must report net.ErrClosed after Close even while a handler is still
// trying to hand off a connection.
func TestListenerAcceptAfterClose(t *testing.T) {
	s := &Service{}
	s.mu.listeners = map[uint16]*tcpListener{}
	l := &tcpListener{
		port:   1234,
		s:      s,
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}
	s.mu.listeners[l.port] = l
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Keep a send pending so every Accept has a connection ready alongside closed.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			server, client := net.Pipe()
			_ = client.Close()
			select {
			case l.accept <- server:
			case <-stop:
				_ = server.Close()
				return
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	for range 100 {
		time.Sleep(time.Millisecond)
		conn, err := l.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: got err %v, want net.ErrClosed", err)
		}
	}
}
