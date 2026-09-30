package nebula

import (
	"bytes"
	"flag"
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
// rather than a rewrite. Regenerate with `go test ./... -run TestSSHCommandSurface -update`.
var updateGolden = flag.Bool("update", false, "update golden files")

func TestSSHCommandSurface(t *testing.T) {
	got := renderCommandSurface(registeredCommands(t).Schema())
	test.Golden(t, filepath.Join("testdata", "ssh_commands.golden"), got, *updateGolden)
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
// serves. Commands are served by default, so this test is what turns "somebody forgot to
// think about it" into a visible decision: adding a command fails here until the lists
// below say where it belongs.
func TestLocalSocketSurface(t *testing.T) {
	reg := registeredCommands(t)

	var served, withheld []commands.Name
	for _, c := range reg.All() {
		if c.ForProfiling {
			withheld = append(withheld, c.Name)
		} else {
			served = append(served, c.Name)
		}
	}

	// The profiling commands stay off this surface and remain one workflow on the ssh
	// debug server, where sshd.sandbox_dir governs where their output lands.
	assert.ElementsMatch(t, []commands.Name{
		commands.StartCPUProfile,
		commands.StopCPUProfile,
		commands.SaveHeapProfile,
		commands.MutexProfileFraction,
		commands.SaveMutexProfile,
	}, withheld)

	assert.ElementsMatch(t, []commands.Name{
		commands.Help,
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

// TestKnownNamesAreTheRegisteredSet holds commands.Known to what nebula registers: every
// name there is registered by attachCommands or, for logout, by the ssh session, and
// nothing is registered under a name that is not there. Known is also the display
// order, so a command missing from it would list last rather than where it belongs.
func TestKnownNamesAreTheRegisteredSet(t *testing.T) {
	reg := registeredCommands(t)

	// Registered per ssh session on a clone of this registry; see sshd.NewSession.
	got := []commands.Name{commands.Logout}
	for _, c := range reg.All() {
		got = append(got, c.Name)
	}

	assert.ElementsMatch(t, commands.Known[:], got)
}
