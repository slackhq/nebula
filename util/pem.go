package util

import (
	"bufio"
	"bytes"
)

// SplitPEM is a split function for bufio.Scanner that returns each PEM block.
func SplitPEM(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Look for the start of a PEM block
	start := bytes.Index(data, []byte("-----BEGIN "))
	if start == -1 {
		if atEOF && len(data) > 0 {
			// No PEM block found, skip remaining data
			return len(data), nil, nil
		}
		// Request more data
		return 0, nil, nil
	}

	// Look for the end marker
	endMarkerStart := bytes.Index(data[start:], []byte("-----END "))
	if endMarkerStart == -1 {
		if atEOF {
			// Incomplete PEM block at EOF
			return 0, nil, bufio.ErrFinalToken
		}
		// Need more data to find the end
		return 0, nil, nil
	}

	// Find the actual end of the END line (after the newline)
	endMarkerStart += start
	endLineEnd := bytes.IndexByte(data[endMarkerStart:], '\n')
	if endLineEnd == -1 {
		if atEOF {
			// END marker without newline at EOF - take it anyway
			endLineEnd = len(data) - endMarkerStart
		} else {
			// Need more data
			return 0, nil, nil
		}
	}

	end := endMarkerStart + endLineEnd + 1

	// Extract the PEM block
	pemBlock := data[start:end]

	// Return the valid PEM block
	return end, pemBlock, nil
}
