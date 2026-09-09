package nebula

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attachedCommands is every command nebula exposes. The ssh console and `nebula ctl` dispatch
// against this one set, so this list is the contract for both transports.
var attachedCommands = []string{
	"change-remote",
	"close-tunnel",
	"create-tunnel",
	"device-info",
	"list-hostmap",
	"list-lighthouse-addrmap",
	"list-pending-hostmap",
	"log-format",
	"log-level",
	"mutex-profile-fraction",
	"print-cert",
	"print-relays",
	"print-tunnel",
	"query-lighthouse",
	"reload",
	"save-heap-profile",
	"save-mutex-profile",
	"start-cpu-profile",
	"stop-cpu-profile",
	"version",
}

func TestAttachCommands(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	reg := diag.NewRegistry()

	// The callbacks capture these but do not touch them until a command runs, and this test
	// only registers and asks for help.
	attachCommands(l, config.NewC(l), reg, &Interface{})

	t.Run("every command is registered", func(t *testing.T) {
		for _, name := range attachedCommands {
			assert.Equal(t, []string{name}, reg.Match(name), "%s is not registered", name)
		}
	})

	t.Run("help is available for every command", func(t *testing.T) {
		for _, name := range attachedCommands {
			buf := &bytes.Buffer{}
			require.NoError(t, reg.DispatchArgs([]string{"help", name}, diag.NewWriter(buf)), name)
			assert.Contains(t, buf.String(), name+" - ", name)
		}
	})

	t.Run("the command list names them all", func(t *testing.T) {
		buf := &bytes.Buffer{}
		require.NoError(t, reg.DispatchArgs(nil, diag.NewWriter(buf)))

		for _, name := range attachedCommands {
			assert.Contains(t, buf.String(), name+" - ", name)
		}
	})
}
