package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_help(t *testing.T) {
	expected := "Usage of " + os.Args[0] + " <global flags> <mode>:\n" +
		"  Global flags:\n" +
		"    -version: Prints the version\n" +
		"    -h, -help: Prints this help message\n\n" +
		"  Modes:\n" +
		"    " + caSummary() + "\n" +
		"    " + keygenSummary() + "\n" +
		"    " + signSummary() + "\n" +
		"    " + printSummary() + "\n" +
		"    " + verifySummary() + "\n" +
		"\n" +
		"  To see usage for a given mode, use " + os.Args[0] + " <mode> -h\n"

	ob := &bytes.Buffer{}

	// No error test
	help("", ob)
	assert.Equal(
		t,
		expected,
		ob.String(),
	)

	// Error test
	ob.Reset()
	help("test error", ob)
	assert.Equal(
		t,
		"Error: test error\n\n"+expected,
		ob.String(),
	)
}

func Test_handleError(t *testing.T) {
	ob := &bytes.Buffer{}

	// normal error
	handleError("", errors.New("test error"), ob)
	assert.Equal(t, "Error: test error\n", ob.String())

	// unknown mode help error
	ob.Reset()
	handleError("", newHelpErrorf("test %s", "error"), ob)
	assert.Equal(t, "Error: test error\n", ob.String())

	// test all modes with help error
	modes := map[string]func(io.Writer){"ca": caHelp, "print": printHelp, "sign": signHelp, "verify": verifyHelp}
	eb := &bytes.Buffer{}
	for mode, fn := range modes {
		ob.Reset()
		eb.Reset()
		fn(eb)

		handleError(mode, newHelpErrorf("test %s", "error"), ob)
		assert.Equal(t, "Error: test error\n"+eb.String(), ob.String())
	}

}

func assertHelpError(t *testing.T, err error, msg string) {
	switch err.(type) {
	case *helpError:
		// good
	default:
		t.Fatal(fmt.Sprintf("err was not a helpError: %q, expected %q", err, msg))
	}

	require.EqualError(t, err, msg)
}

func optionalPkcs11String(msg string) string {
	if p11Supported() {
		return msg
	} else {
		return ""
	}
}
