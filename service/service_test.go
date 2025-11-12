package service

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
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

	logger := logrus.New()
	logger.Out = os.Stdout

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

func TestService(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	a := newSimpleService(ca, caKey, "a", netip.MustParseAddr("10.0.0.1"), m{
		"static_host_map": m{},
		"lighthouse": m{
			"am_lighthouse": true,
		},
		"listen": m{
			"host": "0.0.0.0",
			"port": 4243,
		},
	})
	b := newSimpleService(ca, caKey, "b", netip.MustParseAddr("10.0.0.2"), m{
		"static_host_map": m{
			"10.0.0.1": []string{"localhost:4243"},
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
