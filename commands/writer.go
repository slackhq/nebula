package commands

import "io"

// Output is where a command line surface's text goes.
//
// Out and Err are distinct so a command's primary output can stay machine readable on
// a surface that separates the two. The ssh surface points both at the same channel,
// which is why it sees a single merged stream exactly as it always has. The local
// control socket does not use one at all: it invokes by named parameter and carries the
// returned value, so there is no stream for a command to write to.
type Output struct {
	// Out receives what a command produces.
	Out io.Writer

	// Err receives usage text, refusals and errors.
	Err io.Writer
}

// MergedOutput sends output and errors to the same writer.
func MergedOutput(w io.Writer) Output {
	return Output{Out: w, Err: w}
}
