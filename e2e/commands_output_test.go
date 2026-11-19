//go:build e2e_testing

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/localapi"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

// volatile lists everything in command output that legitimately differs between runs.
// Each run mints fresh certificates and indexes, so these are replaced with a marker
// before comparison. Keep the list short: anything added here is something the golden
// stops guarding.
var volatile = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`[0-9a-f]{40,}`), "<hex>"},                                                       // fingerprints, keys, signatures
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`), "<time>"}, // RFC 3339
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? [+-]\d{4} \w+`), "<time>"},        // time.Time.String()
	{regexp.MustCompile(`(?s)(-----BEGIN [A-Z ]+-----\n).*?(\n-----END [A-Z ]+-----)`), "${1}<pem>${2}"}, // print-cert -raw
	{regexp.MustCompile(`(-----BEGIN [A-Z ]+-----\\n).*?(\\n-----END [A-Z ]+-----)`), "${1}<pem>${2}"},   // the same, inside a JSON string
	{regexp.MustCompile(`"(localIndex|remoteIndex|messageCounter)":\d+`), `"$1":<n>`},
	{regexp.MustCompile(`(?m)^(\s*"?(?:LocalIndex|RemoteIndex|localIndex|remoteIndex|messageCounter)"?:?\s*)\d+`), "${1}<n>"}, // and the -pretty form
}

func normalise(s string) string {
	for _, v := range volatile {
		s = v.re.ReplaceAllString(s, v.with)
	}
	return s
}

// outputCase is one command line to send to the control socket.
type outputCase struct {
	name string
	args []string
}

// TestCommandOutput pins the bytes every command produces, in every format, through the
// control socket. A change here is a change someone running nebula ctl would see.
// Regenerate with:
//
//	go test -tags e2e_testing ./e2e -run TestCommandOutput -update
func TestCommandOutput(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(
		cert.Version1, cert.Curve_CURVE25519,
		time.Now(), time.Now().Add(10*time.Minute),
		nil, nil, []string{},
	)

	control, _, _, _ := newSimpleServer(cert.Version1, ca, caKey, "output-golden", "10.222.0.1/24", nil)
	control.Start()
	t.Cleanup(func() { control.Stop() })

	srv := localapi.NewServer(test.NewLogger(), control.Commands())
	// The control socket is a named pipe on windows and a unix socket everywhere else.
	path := fmt.Sprintf(`\\.\pipe\nebula-output-golden-%d`, os.Getpid())
	if runtime.GOOS != "windows" {
		path = filepath.Join(test.ShortTempDir(t), "s.sock")
	}
	require.NoError(t, srv.Rebind(context.Background(), path, localapi.OwnerOnly()))
	t.Cleanup(srv.Stop)

	client := &localapi.Client{Path: path}

	// run sends a line as nebula ctl does and returns what it would print, with an error
	// where it would exit 1.
	run := func(args ...string) (string, error) {
		return runCtl(client, args)
	}

	// Seed a pending tunnel so the listing and per-address commands have something to show.
	seed, err := run("create-tunnel", "10.222.0.9")
	require.NoError(t, err)
	require.Equal(t, "Created\n", seed, "seeding a tunnel should succeed before anything else is recorded")

	cases := []outputCase{
		{"version", nil},
		{"device-info", nil},
		{"list-hostmap", nil},
		{"list-hostmap", []string{"-by-index"}},
		{"list-pending-hostmap", nil},
		{"list-pending-hostmap", []string{"-by-index"}},
		{"list-lighthouse-addrmap", nil},
		{"print-cert", nil},
		{"print-cert", []string{"-raw"}},
		{"print-cert", []string{"10.222.0.9"}},
		// A flag after the operand is still a flag.
		{"print-cert", []string{"10.222.0.9", "-json"}},
		{"print-cert", []string{"10.222.0.250"}},
		{"print-cert", []string{"not-an-address"}},
		// No address is this node; so is our own address, which the hostmap never holds.
		{"identity", nil},
		{"identity", []string{"-pem"}},
		{"identity", []string{"-pem", "10.222.0.1"}},
		{"identity", []string{"-pem", "10.222.0.9"}},
		{"identity", []string{"10.222.0.1"}},
		{"identity", []string{"10.222.0.1:4242"}},
		// A pending tunnel has no certificate yet.
		{"identity", []string{"10.222.0.9"}},
		{"identity", []string{"not-an-address"}},
		// An empty address is a caller's mistake, never this node.
		{"identity", []string{""}},
		{"identity", []string{"10.222.0.1", "10.222.0.9"}},
		{"print-tunnel", nil},
		{"print-tunnel", []string{"10.222.0.9"}},
		{"print-tunnel", []string{"10.222.0.250"}},
		{"print-relays", nil},
		{"query-lighthouse", nil},
		{"query-lighthouse", []string{"10.222.0.9"}},
		{"query-lighthouse", []string{"not-an-address"}},
		// The test logger cannot change level or format, so these cases record the
		// refusal each command prints on it, not a successful change.
		{"log-level", nil},
		{"log-level", []string{"debug"}},
		{"log-level", []string{"bogus"}},
		{"log-level", []string{"info"}},
		{"log-format", nil},
		{"log-format", []string{"json"}},
		{"log-format", []string{"text"}},
		{"change-remote", nil},
		{"change-remote", []string{"10.222.0.9"}},
		{"change-remote", []string{"-address", "10.94.0.10:4242", "10.222.0.9"}},
		{"change-remote", []string{"-address", "10.94.0.10:4242", "10.222.0.250"}},
		{"create-tunnel", nil},
		{"create-tunnel", []string{"10.222.0.9"}},
		// A fresh address, so this exercises the handshake start with a remote attached
		// rather than the "already handshaking" path above.
		{"create-tunnel", []string{"-address", "10.94.0.10:4242", "10.222.0.10"}},
		{"create-tunnel", []string{"not-an-address"}},
		{"close-tunnel", nil},
		{"close-tunnel", []string{"10.222.0.250"}},
		{"close-tunnel", []string{"not-an-address"}},
		{"help", nil},
		{"help", []string{"print-cert"}},
		{"print-cert", []string{"-h"}},
		{"not-a-command", []string{"10.222.0.9"}},
		// reload is last so that whatever a reload does to the daemon cannot leak into an
		// earlier case. In this harness it fails: the config was loaded from a string and
		// has no path to re-read, which is what the recorded result says.
		{"reload", nil},
	}

	got := &strings.Builder{}
	for _, c := range cases {
		for _, fmtFlags := range [][]string{nil, {"-json"}, {"-pretty"}} {
			args := append([]string{c.name}, fmtFlags...)
			args = append(args, c.args...)

			fmt.Fprintf(got, "$ %s\n", strings.Join(args, " "))
			out, err := run(args...)
			out = normalise(out)
			got.WriteString(out)
			// Output that does not end in a newline is recorded as such, the way diff marks
			// it, so the golden sees that byte too and the next prompt still starts a line.
			if out != "" && !strings.HasSuffix(out, "\n") {
				got.WriteString("\\ No newline at end of output\n")
			}
			// A failed command is recorded as the exit status nebula ctl gives, so the
			// golden pins which outcomes count as failures.
			if err != nil {
				got.WriteString("exit status 1\n")
			}
			got.WriteString("\n")
		}
	}

	test.Golden(t, filepath.Join("testdata", "commands_output.golden"), got.String())
}

// runCtl runs a line through InvokeLine, as nebula ctl does, and returns what nebula ctl
// would print, stdout and stderr together.
func runCtl(client *localapi.Client, args []string) (string, error) {
	buf := &strings.Builder{}
	out, err := client.InvokeLine(args, "nebula ctl", buf)
	if out != "" {
		buf.WriteString(out)
		if !strings.HasSuffix(out, "\n") {
			buf.WriteString("\n")
		}
	}

	// A JSON refusal is already in out; anything else is printed the way nebula ctl
	// prints it on stderr.
	if err != nil && out == "" {
		var refused *localapi.DaemonError
		if errors.As(err, &refused) {
			buf.WriteString(strings.TrimSuffix(refused.Msg, "\n") + "\n")
		} else {
			fmt.Fprintf(buf, "nebula: %s\n", err)
		}
	}
	return buf.String(), err
}
