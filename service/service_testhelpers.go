package service

import (
	"fmt"
	"net/netip"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/e2e"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

func newSimpleService(caCrt *cert.NebulaCertificate, caKey []byte, name string, udpIp netip.Addr, overrides m) *Service {
	_, _, myPrivKey, myPEM := e2e.NewTestCert(caCrt, caKey, "a", time.Now(), time.Now().Add(5*time.Minute), netip.PrefixFrom(udpIp, 24), nil, []string{})
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
	s, err := New(&c, l)
	if err != nil {
		panic(err)
	}
	return s
}

func CreateTwoConnectedServices(port int) (*Service, *Service) {
	ca, _, caKey, _ := e2e.NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	a := newSimpleService(ca, caKey, "a", netip.MustParseAddr("10.0.0.1"), m{
		"static_host_map": m{},
		"lighthouse": m{
			"am_lighthouse": true,
		},
		"listen": m{
			"host": "0.0.0.0",
			"port": port,
		},
	})
	b := newSimpleService(ca, caKey, "b", netip.MustParseAddr("10.0.0.2"), m{
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