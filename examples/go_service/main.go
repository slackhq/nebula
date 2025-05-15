package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() error {
	configStr := `
tun:
  user: true

static_host_map:
  '192.168.100.1': ['localhost:4242']

listen:
  host: 0.0.0.0
  port: 4241

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - '192.168.100.1'

firewall:
  outbound:
    # Allow all outbound traffic from this node
    - port: any
      proto: any
      host: any

  inbound:
    # Allow icmp between any nebula hosts
    - port: any
      proto: icmp
      host: any
    - port: any
      proto: any
      host: any

pki:
  ca: /home/rice/Developer/nebula-config/ca.crt
  cert: /home/rice/Developer/nebula-config/app.crt
  key: /home/rice/Developer/nebula-config/app.key
`
	var cfg config.C
	if err := cfg.LoadString(configStr); err != nil {
		return err
	}

	logger := logrus.New()
	logger.Out = os.Stdout

	ctrl, err := nebula.Main(&cfg, false, "custom-app", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		return err
	}

	svc, err := service.New(ctrl)
	if err != nil {
		return err
	}

	ln, err := svc.Listen("tcp", ":1234")
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			break
		}
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)

		log.Printf("got connection")

		_, err = conn.Write([]byte("hello world\n"))
		if err != nil {
			log.Printf("write error: %s", err)
		}

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			message := scanner.Text()
			_, err = fmt.Fprintf(conn, "echo: %q\n", message)
			if err != nil {
				log.Printf("write error: %s", err)
			}
			log.Printf("got message %q", message)
		}

		if err := scanner.Err(); err != nil {
			log.Printf("scanner error: %s", err)
			break
		}
	}

	_ = svc.Close()
	if err := svc.Wait(); err != nil {
		return err
	}
	return nil
}
