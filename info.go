package nebula

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// TODO Firm up how we return errors and accept messages + data

type Message struct {
	Command string `json:"command"`
	Data    string `json:"data"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func handleHostmapList(l *logrus.Logger, hm *HostMap) ([]byte, error) {
	type HostListItem struct {
		VpnAddrs []netip.Addr `json:"vpnAddrs"`
		//Remote            netip.AddrPort `json:"remote"`
		Relayed           bool      `json:"relayed,omitempty"`
		LastHandshakeTime time.Time `json:"lastHandshakeTime"`
		Groups            []string  `json:"groups"`
	}
	out := map[string]HostListItem{}
	hm.ForEachVpnAddr(func(hi *HostInfo) {
		cert := hi.GetCert().Certificate
		out[cert.Name()] = HostListItem{
			VpnAddrs: hi.vpnAddrs,
			//Remote:            hi.remote,
			Relayed:           !hi.remote.IsValid(),
			LastHandshakeTime: time.Unix(0, int64(hi.lastHandshakeTime)),
			Groups:            cert.Groups(),
		}
	})
	js, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("json error: %w", err)
	}
	return js, nil
}

func handleHostCertLookup(l *logrus.Logger, hm *HostMap, msg *Message) ([]byte, error) {
	ipStr := msg.Data //TODO how do we want to structure this? What if we expand to more ssh commands?
	if ipStr == "" {
		return nil, fmt.Errorf("you must provide an IP address")
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		//todo filter non-Nebula IPs?
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	hi := hm.QueryVpnAddr(addr)
	if hi == nil {
		return nil, fmt.Errorf("ip address not found: %s", ipStr)
	} else if hi.ConnectionState == nil {
		return nil, fmt.Errorf("host not connected: %s", ipStr)
	}
	out, err := hi.ConnectionState.peerCert.Certificate.MarshalJSON()
	if err != nil {
		l.WithError(err).Error("failed to marshal peer certificate")
		return nil, fmt.Errorf("failed to marshal peer certificate: %w", err)
	}
	return out, nil
}

func startInfo(l *logrus.Logger, c *config.C, configTest bool, hm *HostMap) (func(), error) {
	listenAddr := c.GetString("info.listen", "")
	var startFn func()
	if configTest {
		//TODO validate that listenAddr is an acceptable value as part of the config test
		return startFn, nil
	}
	if err := os.RemoveAll(listenAddr); err != nil {
		l.WithError(err).Fatal("failed to remove unix socket")
	}
	startFn = func() {
		listener, err := net.Listen("unix", listenAddr)
		if err != nil {
			log.Fatalf("Failed to listen on unix socket: %v", err)
		}
		defer listener.Close()
		defer os.Remove(listenAddr)
		l.WithField("bind", listenAddr).Info("Info listener starting")
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024) // Arbitrary
				n, err := c.Read(buf)
				if err != nil {
					l.WithError(err).Error("Failed to read from connection")
					return
				}
				var msg Message
				if err := json.Unmarshal(buf[:n], &msg); err != nil {
					l.WithError(err).Error("Failed to unmarshal JSON")
					return
				}
				l.WithField("command", msg.Command).WithField("Data", msg.Data).Debug("Received Command")
				err = handleCommand(l, c, hm, &msg)
				if err != nil {
					l.WithError(err).Error("Failed to handle command")
					out, err := json.Marshal(ErrorResponse{Error: err.Error()})
					if err != nil {
						l.WithError(err).Error("Failed to marshal error response")
						return
					}
					c.Write(out)
					return
				}
			}(conn)
		}
	}
	return startFn, nil
}

// maybe we can add more of the supported SSH commands here?
func handleCommand(l *logrus.Logger, c net.Conn, hm *HostMap, msg *Message) error {
	switch msg.Command {
	case "ping": // TODO remove test command
		c.Write([]byte("pong\n"))
	case "hostmap":
		out, err := handleHostmapList(l, hm)
		if err != nil {
			return err
		}
		c.Write(out)
	case "hostinfo":
		out, err := handleHostCertLookup(l, hm, msg)
		if err != nil {
			return err
		}
		c.Write(out)
	default:
		c.Write([]byte("unknown command\n"))
	}
	return nil
}
