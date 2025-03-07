package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"golang.org/x/sync/errgroup"
)

func TestService(t *testing.T) {
	a, _, b, _ := CreateTwoConnectedServices(t, 4243)

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
}
