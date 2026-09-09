package diag

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestRoundTrip(t *testing.T) {
	t.Run("argv survives a round trip, spaces and all", func(t *testing.T) {
		buf := &bytes.Buffer{}
		args := []string{"start-cpu-profile", "/tmp/a path.pb.gz", "-json"}
		require.NoError(t, writeRequest(buf, args))

		req, err := readRequest(bufio.NewReader(buf))
		require.NoError(t, err)
		assert.Equal(t, ProtoVersion, req.Version)
		assert.Equal(t, args, req.Args)
	})

	t.Run("an unknown version is refused by name", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader(`{"version":99,"args":["version"]}` + "\n"))

		_, err := readRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported protocol version 99")
	})

	t.Run("malformed json is refused", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("not json\n"))

		_, err := readRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed request")
	})

	t.Run("a line without a newline is bounded rather than buffered forever", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader(strings.Repeat("a", maxRequest+10)))

		_, err := readRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "without a newline")
	})
}

func TestResponseRoundTrip(t *testing.T) {
	t.Run("output and status survive a round trip", func(t *testing.T) {
		wire := &bytes.Buffer{}
		w := bufio.NewWriterSize(&frameWriter{w: wire}, outputBuffer)
		require.NoError(t, NewWriter(w).WriteLine("hello"))
		require.NoError(t, w.Flush())
		require.NoError(t, writeEnd(wire, StatusOK, ""))

		out := &bytes.Buffer{}
		status, err := readResponse(wire, out)
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, "hello\n", out.String())
	})

	// print-cert -raw and list-hostmap -json both emit arbitrary bytes, so a payload larger
	// than one frame has to reassemble exactly.
	t.Run("a payload larger than one frame reassembles byte for byte", func(t *testing.T) {
		big := bytes.Repeat([]byte("nebula"), maxFrame)

		wire := &bytes.Buffer{}
		fw := &frameWriter{w: wire}
		n, err := fw.Write(big)
		require.NoError(t, err)
		require.Equal(t, len(big), n)
		require.NoError(t, writeEnd(wire, StatusOK, ""))

		out := &bytes.Buffer{}
		status, err := readResponse(wire, out)
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, big, out.Bytes())
	})

	t.Run("a non-zero status carries its message", func(t *testing.T) {
		wire := &bytes.Buffer{}
		require.NoError(t, writeEnd(wire, StatusError, "it went wrong"))

		status, err := readResponse(wire, &bytes.Buffer{})
		require.Error(t, err)
		assert.Equal(t, StatusError, status)
		assert.Contains(t, err.Error(), "it went wrong")
	})

	// This is how the CLI notices a nebula that died mid-command rather than silently
	// reporting whatever partial output it managed to read.
	t.Run("a stream ending without an end frame is truncated, not successful", func(t *testing.T) {
		wire := &bytes.Buffer{}
		_, err := (&frameWriter{w: wire}).Write([]byte("partial"))
		require.NoError(t, err)

		out := &bytes.Buffer{}
		_, err = readResponse(wire, out)
		assert.ErrorIs(t, err, ErrTruncated)
	})

	t.Run("a truncated frame header is truncated, not successful", func(t *testing.T) {
		_, err := readResponse(bytes.NewReader([]byte{frameOutput, 0x00}), &bytes.Buffer{})
		assert.ErrorIs(t, err, ErrTruncated)
	})

	t.Run("an oversized frame is refused rather than allocated", func(t *testing.T) {
		var hdr [5]byte
		hdr[0] = frameOutput
		binary.BigEndian.PutUint32(hdr[1:], maxFrame+1)

		_, err := readResponse(bytes.NewReader(hdr[:]), &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})

	// A reserved frame an older client does not understand must not break it.
	t.Run("a reserved frame type is skipped", func(t *testing.T) {
		wire := &bytes.Buffer{}
		require.NoError(t, writeFrame(wire, frameStderr, []byte("future")))
		require.NoError(t, writeFrame(wire, frameOutput, []byte("now")))
		require.NoError(t, writeEnd(wire, StatusOK, ""))

		out := &bytes.Buffer{}
		status, err := readResponse(wire, out)
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, "now", out.String())
	})

	t.Run("an unknown frame type is an error", func(t *testing.T) {
		wire := &bytes.Buffer{}
		require.NoError(t, writeFrame(wire, 0x7f, nil))

		_, err := readResponse(wire, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown frame type")
	})
}
