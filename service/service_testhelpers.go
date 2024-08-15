package service

import (
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/e2e"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

type LogOutputWithPrefix struct {
	prefix string
	out    io.Writer
}

func (o LogOutputWithPrefix) Write(p []byte) (n int, err error) {
	fmt.Fprintf(o.out, "[%s] ", o.prefix)
	return o.out.Write(p)
}

func newSimpleService(caCrt *cert.NebulaCertificate, caKey []byte, name string, udpIp netip.Addr, overrides m) *Service {
	_, _, myPrivKey, myPEM := e2e.NewTestCert(caCrt, caKey, name,
		time.Now().Add(-3*time.Minute),
		time.Now().Add(30*time.Minute),
		netip.PrefixFrom(udpIp, 24), nil, []string{})
	caB, err := caCrt.MarshalToPEM()
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

	l := logrus.New()
	prefixWriter := LogOutputWithPrefix{
		prefix: name,
		out:    l.Out,
	}
	l.SetOutput(prefixWriter)

	s, err := New(&c, l)
	if err != nil {
		panic(err)
	}
	return s
}

func CreateTwoConnectedServices(t *testing.T, port int) (*Service, *Service) {
	port += 100 * (rand.Int() % 10)
	ca, _, caKey, _ := e2e.NewTestCaCert(
		time.Now().Add(-9*time.Minute), // ensure that there is no issue due to rounding
		time.Now().Add(40*time.Minute), // ensure that the certificate is valid for at least the time ot the test execution
		nil, nil, []string{})
	a := newSimpleService(ca, caKey, fmt.Sprintf("a_port_%d_test_name_%s", port, t.Name()), netip.MustParseAddr("10.0.0.1"), m{
		"static_host_map": m{},
		"lighthouse": m{
			"am_lighthouse": true,
		},
		"listen": m{
			"host": "0.0.0.0",
			"port": port,
		},
	})
	b := newSimpleService(ca, caKey, fmt.Sprintf("b_port_%d_test_name_%s", port, t.Name()), netip.MustParseAddr("10.0.0.2"), m{
		"static_host_map": m{
			"10.0.0.1": []string{fmt.Sprintf("localhost:%d", port)},
		},
		"lighthouse": m{
			"hosts":    []string{"10.0.0.1"},
			"interval": 1,
		},
	})
	return a, b
}
