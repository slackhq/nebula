package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// newTCPConnPair returns two connected net.Conn via TCP loopback.
// net.Pipe() is intentionally avoided: SSH handshakes require both sides
// to write simultaneously (kexInit, auth), which deadlocks on an
// unbuffered synchronous pipe. TCP loopback provides kernel buffering.
func newTCPConnPair(t *testing.T) (serverConn net.Conn, clientConn net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		ch <- dialResult{c, err}
	}()

	s, err := ln.Accept()
	require.NoError(t, err)
	ln.Close()

	r := <-ch
	require.NoError(t, r.err)

	t.Cleanup(func() {
		s.Close()
		r.conn.Close()
	})

	return s, r.conn
}

// newTestSSHServer creates a minimal SSHServer with an ephemeral ed25519 host key.
// If addAuthorizedKey is true, the returned signer's public key is registered for "testuser".
func newTestSSHServer(t *testing.T, addAuthorizedKey bool) (*SSHServer, ssh.Signer) {
	t.Helper()

	l := test.NewLogger()
	server, err := NewSSHServer(l.WithField("subsystem", "sshd"))
	require.NoError(t, err)

	// Generate ephemeral host key.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKeyBlock, err := ssh.MarshalPrivateKey(hostPriv, "")
	require.NoError(t, err)
	require.NoError(t, server.SetHostKey(pem.EncodeToMemory(hostKeyBlock)))

	// Generate ephemeral client key.
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	require.NoError(t, err)

	if addAuthorizedKey {
		authorizedKey := string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))
		require.NoError(t, server.AddAuthorizedKey("testuser", authorizedKey))
	}

	return server, clientSigner
}

func newClientConfig(user string, signer ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test only
	}
}

// TestHandshakeWithTimeout_Success verifies that a valid SSH handshake completes
// and returns a non-nil ServerConn with the correct user extensions.
func TestHandshakeWithTimeout_Success(t *testing.T) {
	server, clientSigner := newTestSSHServer(t, true)
	serverConn, clientConn := newTCPConnPair(t)

	type clientResult struct {
		conn ssh.Conn
		err  error
	}
	clientDone := make(chan clientResult, 1)
	go func() {
		c, chans, reqs, err := ssh.NewClientConn(clientConn, "", newClientConfig("testuser", clientSigner))
		if err == nil {
			go ssh.DiscardRequests(reqs)
			go func() {
				for range chans {
				}
			}()
		}
		clientDone <- clientResult{c, err}
	}()
	t.Cleanup(func() {
		if r := <-clientDone; r.conn != nil {
			r.conn.Close()
		}
	})

	conn, chans, reqs, err := server.handshakeWithTimeout(serverConn, 5*time.Second)

	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.NotNil(t, chans)
	assert.NotNil(t, reqs)
	assert.Equal(t, "testuser", conn.Permissions.Extensions["user"])
	conn.Close()
}

// TestHandshakeWithTimeout_HandshakeError verifies that an authentication failure
// (unknown user) is returned as an error without triggering the timeout path.
func TestHandshakeWithTimeout_HandshakeError(t *testing.T) {
	// Server has no authorized keys → any client will be rejected.
	server, clientSigner := newTestSSHServer(t, false)
	serverConn, clientConn := newTCPConnPair(t)

	clientDone := make(chan error, 1)
	go func() {
		_, _, _, err := ssh.NewClientConn(clientConn, "", newClientConfig("testuser", clientSigner))
		clientDone <- err
	}()
	t.Cleanup(func() { <-clientDone })

	conn, chans, reqs, err := server.handshakeWithTimeout(serverConn, 5*time.Second)

	require.Error(t, err)
	assert.NotEqual(t, "handshake timeout", err.Error())
	assert.Nil(t, conn)
	assert.Nil(t, chans)
	assert.Nil(t, reqs)
}

// TestHandshakeWithTimeout_Timeout verifies that when no client sends SSH traffic,
// the function returns a "handshake timeout" error and closes the connection.
func TestHandshakeWithTimeout_Timeout(t *testing.T) {
	server, _ := newTestSSHServer(t, true)
	serverConn, _ := newTCPConnPair(t)
	// The client side is intentionally idle — no SSH traffic is sent.

	conn, chans, reqs, err := server.handshakeWithTimeout(serverConn, 1*time.Millisecond)

	require.EqualError(t, err, "handshake timeout")
	assert.Nil(t, conn)
	assert.Nil(t, chans)
	assert.Nil(t, reqs)

	// Confirm that handshakeWithTimeout closed the connection.
	_, writeErr := serverConn.Write([]byte("probe"))
	assert.Error(t, writeErr, "serverConn should be closed after timeout")
}
