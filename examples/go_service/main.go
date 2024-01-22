package main

import (
	"bufio"
	"fmt"
	"log"

	"github.com/slackhq/nebula/config"
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
	var config config.C
	if err := config.LoadString(configStr); err != nil {
		return err
	}
	service, err := service.New(&config)
	if err != nil {
		return err
	}

	ln, err := service.Listen("tcp", ":1234")
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			break
		}
		defer conn.Close()

		log.Printf("got connection")

		conn.Write([]byte("hello world\n"))

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			message := scanner.Text()
			fmt.Fprintf(conn, "echo: %q\n", message)
			log.Printf("got message %q", message)
		}

		if err := scanner.Err(); err != nil {
			log.Printf("scanner error: %s", err)
			break
		}
	}

	service.Close()
	if err := service.Wait(); err != nil {
		return err
	}
	return nil
}
