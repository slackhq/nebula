package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// A version string that can be set with
//
//	-ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func init() {
	if Build == "" {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}

		Build = strings.TrimPrefix(info.Main.Version, "v")
	}
}

type helpError struct {
	s string
}

func (he *helpError) Error() string {
	return he.s
}

func newHelpErrorf(s string, v ...any) error {
	return &helpError{s: fmt.Sprintf(s, v...)}
}

func main() {
	flag.Usage = func() {
		help("", os.Stderr)
		os.Exit(1)
	}

	printVersion := flag.Bool("version", false, "Print version")
	flagHelp := flag.Bool("help", false, "Print command line usage")
	flagH := flag.Bool("h", false, "Print command line usage")
	printUsage := false

	flag.Parse()

	if *flagH || *flagHelp {
		printUsage = true
	}

	args := flag.Args()

	if *printVersion {
		fmt.Printf("Version: %v\n", Build)
		os.Exit(0)
	}

	if len(args) < 1 {
		if printUsage {
			help("", os.Stderr)
			os.Exit(0)
		}

		help("No mode was provided", os.Stderr)
		os.Exit(1)
	} else if printUsage {
		handleError(args[0], &helpError{}, os.Stderr)
		os.Exit(0)
	}

	var err error

	switch args[0] {
	case "ca":
		err = ca(args[1:], os.Stdout, os.Stderr, StdinPasswordReader{})
	case "keygen":
		err = keygen(args[1:], os.Stdout, os.Stderr)
	case "sign":
		err = signCert(args[1:], os.Stdout, os.Stderr, StdinPasswordReader{})
	case "print":
		err = printCert(args[1:], os.Stdout, os.Stderr)
	case "verify":
		err = verify(args[1:], os.Stdout, os.Stderr)
	default:
		err = fmt.Errorf("unknown mode: %s", args[0])
	}

	if err != nil {
		os.Exit(handleError(args[0], err, os.Stderr))
	}
}

func handleError(mode string, e error, out io.Writer) int {
	code := 1

	// Handle -help, -h flags properly
	if e == flag.ErrHelp {
		code = 0
		e = &helpError{}
	} else if e != nil && e.Error() != "" {
		fmt.Fprintln(out, "Error:", e)
	}

	switch e.(type) {
	case *helpError:
		switch mode {
		case "ca":
			caHelp(out)
		case "keygen":
			keygenHelp(out)
		case "sign":
			signHelp(out)
		case "print":
			printHelp(out)
		case "verify":
			verifyHelp(out)
		}
	}

	return code
}

func help(err string, out io.Writer) {
	if err != "" {
		fmt.Fprintln(out, "Error:", err)
		fmt.Fprintln(out, "")
	}

	fmt.Fprintf(out, "Usage of %s <global flags> <mode>:\n", os.Args[0])
	fmt.Fprintln(out, "  Global flags:")
	fmt.Fprintln(out, "    -version: Prints the version")
	fmt.Fprintln(out, "    -h, -help: Prints this help message")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  Modes:")
	fmt.Fprintln(out, "    "+caSummary())
	fmt.Fprintln(out, "    "+keygenSummary())
	fmt.Fprintln(out, "    "+signSummary())
	fmt.Fprintln(out, "    "+printSummary())
	fmt.Fprintln(out, "    "+verifySummary())
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "  To see usage for a given mode, use %s <mode> -h\n", os.Args[0])
}

func mustFlagString(name string, val *string) error {
	if *val == "" {
		return newHelpErrorf("-%s is required", name)
	}
	return nil
}
