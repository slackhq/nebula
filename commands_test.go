package nebula

import (
	"bytes"
	"io"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogFormatRefusalIsShown: a format the logger does not know is reported to the user
// rather than returned bare, which over ssh was silence.
func TestLogFormatRefusalIsShown(t *testing.T) {
	l := logging.NewLogger(io.Discard)
	out := &bytes.Buffer{}
	w := commands.NewStringWriter(out)

	require.NoError(t, sshLogFormat(l, nil, []string{"bogus"}, w))
	assert.Equal(t, "Unable to set log format: unknown log format `bogus`. possible formats: [text json]\n", out.String())

	out.Reset()
	require.NoError(t, sshLogFormat(l, nil, []string{"JSON"}, w))
	assert.Equal(t, "Log format is: json\n", out.String())
}
