//go:build windows

package localapi

import (
	"context"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInfoIsNotServedOnWindows: a pipe has no mode to open to other accounts, so Rebind
// says so and leaves nothing listening, whatever the config asked for.
func TestInfoIsNotServedOnWindows(t *testing.T) {
	s := NewInfoServer(test.NewLogger(), commands.New())
	err := s.Rebind(context.Background(), pipePrefix+"nebula-info-test", Access{Mode: 0600})
	require.ErrorIs(t, err, errInfoUnsupported)
	assert.Empty(t, s.Path())
	s.Stop()
}
