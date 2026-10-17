package nebula

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
)

// TestSSHCommandSurface is a characterization test for the ssh command surface.
// It pins the registered command set, their descriptions, help text and flag definitions
// so that moving the registry to a transport neutral package is provably a relocation
// rather than a rewrite. Regenerate with `go test . -run TestSSHCommandSurface -update`.
func TestSSHCommandSurface(t *testing.T) {
	got := renderCommandSurface(registeredCommands(t).All())
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

	// In the order All gives, so the golden pins display order too.
	return strings.Join(lines, "")
}
