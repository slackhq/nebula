package main

import (
	"fmt"
	"io"
	"os"
)

// stdioPath is the special path value that selects stdin (for inputs) or
// stdout (for outputs) instead of a file on disk.
const stdioPath = "-"

// stdioHelpText is rendered just under the Usage line of each subcommand
// help so the - convention is documented once instead of on every flag.
const stdioHelpText = "  Pass \"-\" to any path flag to read from stdin or write to stdout.\n"

// stdinReader is the source used when an input flag is set to "-".
// It is a package level var so tests can swap in a deterministic reader.
// Tests that mutate stdinReader cannot run with t.Parallel().
var stdinReader io.Reader = os.Stdin

// ioClaims tracks which flags have claimed stdin and stdout during a single
// command invocation so we can refuse a second flag asking for the same
// stream.
type ioClaims struct {
	in  string
	out string
}

func (c *ioClaims) claimIn(flagName string) error {
	if c.in != "" && c.in != flagName {
		return fmt.Errorf("-%s and -%s both set to %q, only one input may read from stdin", c.in, flagName, stdioPath)
	}
	c.in = flagName
	return nil
}

func (c *ioClaims) claimOut(flagName string) error {
	if c.out != "" && c.out != flagName {
		return fmt.Errorf("-%s and -%s both set to %q, only one output may write to stdout", c.out, flagName, stdioPath)
	}
	c.out = flagName
	return nil
}

// reserveInputs walks alternating (flagName, path) pairs and claims stdin
// for any path equal to stdioPath. It must be called before any input is
// read so a conflict can be reported immediately instead of blocking on
// io.ReadAll while waiting for input that will never arrive.
func reserveInputs(claims *ioClaims, pairs ...string) error {
	return reserveStdio(claims, "reserveInputs", (*ioClaims).claimIn, pairs)
}

// reserveOutputs walks alternating (flagName, path) pairs and claims stdout
// for any path equal to stdioPath. It must be called before any output is
// written so a conflict cannot leave one stream half written before the
// second flag fails.
func reserveOutputs(claims *ioClaims, pairs ...string) error {
	return reserveStdio(claims, "reserveOutputs", (*ioClaims).claimOut, pairs)
}

func reserveStdio(claims *ioClaims, who string, claim func(*ioClaims, string) error, pairs []string) error {
	if len(pairs)%2 != 0 {
		panic(who + " requires alternating name, path pairs")
	}
	for i := 0; i < len(pairs); i += 2 {
		name, path := pairs[i], pairs[i+1]
		if path != stdioPath {
			continue
		}
		if err := claim(claims, name); err != nil {
			return err
		}
	}
	return nil
}

// readInput returns the bytes referenced by path, reading from stdin when
// path is stdioPath.
func readInput(flagName, path string, claims *ioClaims) ([]byte, error) {
	if path == stdioPath {
		if err := claims.claimIn(flagName); err != nil {
			return nil, err
		}
		return io.ReadAll(stdinReader)
	}
	return os.ReadFile(path)
}

// openInput returns a reader for path. When path is stdioPath the returned
// reader wraps stdin and Close is a no-op.
func openInput(flagName, path string, claims *ioClaims) (io.ReadCloser, error) {
	if path == stdioPath {
		if err := claims.claimIn(flagName); err != nil {
			return nil, err
		}
		return io.NopCloser(stdinReader), nil
	}
	return os.Open(path)
}

// writeOutput writes data to path, or to stdout when path is stdioPath. perm
// is only used for file output. The caller must have already claimed stdout
// via reserveOutputs before invoking with stdioPath.
func writeOutput(path string, data []byte, perm os.FileMode, stdout io.Writer) error {
	if path == stdioPath {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, perm)
}

// isStdio reports whether path is the stdio sentinel and so should skip
// existence checks like "refuse to overwrite".
func isStdio(path string) bool {
	return path == stdioPath
}
