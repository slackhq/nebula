package nebula

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// TestSSHCommandSurface is a characterization test for the ssh debug command surface.
// It pins the registered command set, their descriptions, help text and flag definitions
// so that moving the registry to a transport neutral package is provably a relocation
// rather than a rewrite. Regenerate with `go test . -run TestSSHCommandSurface -update`.
func TestSSHCommandSurface(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	ssh, err := sshd.NewSSHServer(context.Background(), l)
	require.NoError(t, err)

	// attachCommands only closes over the interface, it does not dereference it while registering.
	attachCommands(l, c, ssh, &Interface{})

	got := renderCommandSurface(ssh.Commands())

	test.Golden(t, filepath.Join("testdata", "ssh_commands.golden"), got, *updateGolden)
}

func renderCommandSurface(cmds []*sshd.Command) string {
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
