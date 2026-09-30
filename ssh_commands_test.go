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
	got := renderCommandSurface(registeredCommands(t).All())
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

func renderCommandSurface(cmds []*commands.Command) string {
	lines := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		b := &bytes.Buffer{}
		fmt.Fprintf(b, "%s\n", cmd.Name)
		fmt.Fprintf(b, "  short: %s\n", cmd.ShortDescription)
		fmt.Fprintf(b, "  help: %s\n", cmd.Help)

		if cmd.Flags != nil {
			fl, _ := cmd.Flags()
			if fl != nil {
				fb := &bytes.Buffer{}
				fl.SetOutput(fb)
				fl.PrintDefaults()
				fmt.Fprintf(b, "  flags:\n%s", fb.String())
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
