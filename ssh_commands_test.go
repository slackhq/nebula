package nebula

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// TestSSHCommandSurface is a characterization test for the ssh command surface.
// It pins the registered command set, their descriptions, help text and flag definitions
// so that moving the registry to a transport neutral package is provably a relocation
// rather than a rewrite. Regenerate with `go test . -run TestSSHCommandSurface -update`.

func TestSSHCommandSurface(t *testing.T) {
	got := renderCommandSurface(registeredCommands(t).Schema())
	test.Golden(t, filepath.Join("testdata", "ssh_commands.golden"), got)
}

// registeredCommands returns a registry holding every command nebula serves. The
// Interface is never dereferenced: attachCommands only closes over it.
func registeredCommands(t *testing.T) *commands.Registry {
	t.Helper()
	l := test.NewLogger()
	reg := commands.New()
	attachCommands(l, config.NewC(l), reg, &Interface{})
	return reg
}

// renderCommandSurface prints what a client actually sees, which is the schema rather
// than the Command structs: the presentation flags are offered on every command that
// returns a value, so reading Command.Flags alone would under-report the surface.
func renderCommandSurface(cmds []commands.CommandSchema) string {
	lines := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		b := &bytes.Buffer{}
		fmt.Fprintf(b, "%s\n", cmd.Name)
		fmt.Fprintf(b, "  short: %s\n", cmd.Short)
		fmt.Fprintf(b, "  help: %s\n", cmd.Help)

		if len(cmd.Flags) > 0 {
			fmt.Fprintf(b, "  flags:\n")
			for _, f := range cmd.Flags {
				kind := " string"
				if f.Bool {
					kind = ""
				}
				fmt.Fprintf(b, "  -%s%s\n    \t%s\n", f.Name, kind, f.Usage)
			}
		}

		lines = append(lines, b.String())
	}

	sort.Strings(lines)
	return joinLines(lines)
}

func joinLines(in []string) string {
	b := &bytes.Buffer{}
	for _, l := range in {
		b.WriteString(l)
	}
	return b.String()
}

// TestLocalSocketSurface pins which of nebula's commands the always-on local socket
// serves: every one registered. Adding a command fails here until the list below says
// so, which turns "somebody forgot to think about it" into a visible decision.
func TestLocalSocketSurface(t *testing.T) {
	var served []commands.Name
	for _, c := range registeredCommands(t).All() {
		served = append(served, c.Name)
	}

	assert.ElementsMatch(t, []commands.Name{
		commands.Help,
		commands.Identity,
		commands.ListHostmap,
		commands.ListPendingHostmap,
		commands.ListLighthouseAddrmap,
		commands.PrintCert,
		commands.PrintTunnel,
		commands.PrintRelays,
		commands.DeviceInfo,
		commands.Version,
		commands.QueryLighthouse,
		commands.Reload,
		commands.LogLevel,
		commands.LogFormat,
		commands.ChangeRemote,
		commands.CloseTunnel,
		commands.CreateTunnel,
	}, served)
}
