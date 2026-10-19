package localapi

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadFrameLimitIsOnTheBody pins the framing rule at its edge: the limit bounds the
// JSON body, so the newline that terminates the frame must not count against it.
func TestReadFrameLimitIsOnTheBody(t *testing.T) {
	// A JSON string whose encoded form is exactly n bytes, with or without a terminator.
	body := func(n int) string {
		return fmt.Sprintf(`"%s"`, strings.Repeat("a", n-2))
	}

	var v string

	// Exactly at the limit, terminated: accepted.
	v = ""
	require.NoError(t, readFrame(bytes.NewReader([]byte(body(64)+"\n")), 64, "request", &v))
	assert.Len(t, v, 62)

	// Exactly at the limit, EOF instead of a newline: still accepted.
	v = ""
	require.NoError(t, readFrame(bytes.NewReader([]byte(body(64))), 64, "request", &v))
	assert.Len(t, v, 62)

	// One byte over: refused as oversized, not as a parse failure.
	err := readFrame(bytes.NewReader([]byte(body(65)+"\n")), 64, "request", &v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded 64 bytes")
}

// stallingReader hands out its bytes and then fails with err, the shape of a peer that
// sends part of a frame and then stops, until the deadline on the connection lands.
type stallingReader struct {
	data []byte
	err  error
}

func (r *stallingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestReadFramePartialLineThenReadErrorIsTheError: a read that fails after part of a
// frame has arrived is a failed read, and the caller sees that error. The old behaviour
// treated the fragment as the whole frame and reported a parse failure, so a client
// that stalled mid request was told its JSON was malformed, and a daemon that stalled
// mid response hid the timeout the client's error path looks for.
func TestReadFramePartialLineThenReadErrorIsTheError(t *testing.T) {
	var v map[string]any

	err := readFrame(&stallingReader{data: []byte(`{"command": "hel`), err: timeoutError{}}, 1024, "request", &v)
	require.Error(t, err)
	var ne net.Error
	require.ErrorAs(t, err, &ne, "the timeout is still visible through the wrapping: %v", err)
	assert.True(t, ne.Timeout())
	assert.NotContains(t, err.Error(), "parse", "a stalled peer is not a parse failure")

	// EOF after an unterminated line is the one exception: a final line with no newline
	// is still a frame.
	v = nil
	require.NoError(t, readFrame(&stallingReader{data: []byte(`{"command": "help"}`), err: io.EOF}, 1024, "request", &v))
	assert.Equal(t, "help", v["command"])

	// And an unterminated line that is EOF only because the limit cut it off is still
	// reported as oversized.
	err = readFrame(bytes.NewReader([]byte(strings.Repeat("a", 70)+"\n")), 64, "request", &v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded 64 bytes")
}
