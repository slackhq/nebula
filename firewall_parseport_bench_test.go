package nebula

// Comparison benchmarks for parsePort's numeric-conversion primitive.
//
// Production parsePort uses strconv.ParseUint(s, 10, 16) (chosen for the
// intrinsic uint16 bounds-checking — see firewall.go:parsePortValue). This
// file pins the methodology used to justify that choice by reproducing the
// same parser shape with three alternative conversion primitives:
//
//   parsePortAtoi     uses strconv.Atoi    + an explicit [0,65535] range check
//   parsePortParseInt uses strconv.ParseInt(_,10,32) + the same range check
//   parsePortManual   uses a hand-rolled byte loop with the bounds inlined
//
// All four variants share the surrounding logic — same "any"/"fragment"
// keywords, same range splitting and trimming, same error wrapping — so
// the only difference timed is the numeric conversion. Run all four with:
//
//   go test -bench='BenchmarkParsePort_(ParseUint|Atoi|ParseInt|Manual)' \
//           -benchmem -count=5 ./...
//
// On a similar input the runner reports ns/op, B/op, allocs/op; pick the
// row labelled SinglePort_typical (the most common shape) to compare.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/slackhq/nebula/firewall"
)

// --- parsePortAtoi: strconv.Atoi + explicit range check ---------------------

func parsePortAtoi(s string) (int32, int32, error) {
	const notAPort int32 = -2
	if s == "any" {
		return firewall.PortAny, firewall.PortAny, nil
	}
	if s == "fragment" {
		return firewall.PortFragment, firewall.PortFragment, nil
	}
	if !strings.Contains(s, `-`) {
		v, err := parsePortValueAtoi("", s)
		if err != nil {
			return notAPort, notAPort, err
		}
		return v, v, nil
	}
	sPorts := strings.SplitN(s, `-`, 2)
	for i := range sPorts {
		sPorts[i] = strings.Trim(sPorts[i], " ")
	}
	if len(sPorts) != 2 || sPorts[0] == "" || sPorts[1] == "" {
		return notAPort, notAPort, fmt.Errorf("appears to be a range but could not be parsed; `%s`", s)
	}
	startPort, err := parsePortValueAtoi("beginning range ", sPorts[0])
	if err != nil {
		return notAPort, notAPort, err
	}
	endPort, err := parsePortValueAtoi("ending range ", sPorts[1])
	if err != nil {
		return notAPort, notAPort, err
	}
	if startPort == firewall.PortAny {
		endPort = firewall.PortAny
	}
	return startPort, endPort, nil
}

func parsePortValueAtoi(prefix, s string) (int32, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%swas not a number; `%s`", prefix, s)
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("%sout of range [0,65535]; `%s`", prefix, s)
	}
	return int32(n), nil
}

// --- parsePortParseInt: strconv.ParseInt(_,10,32) + explicit range check ---

func parsePortParseInt(s string) (int32, int32, error) {
	const notAPort int32 = -2
	if s == "any" {
		return firewall.PortAny, firewall.PortAny, nil
	}
	if s == "fragment" {
		return firewall.PortFragment, firewall.PortFragment, nil
	}
	if !strings.Contains(s, `-`) {
		v, err := parsePortValueParseInt("", s)
		if err != nil {
			return notAPort, notAPort, err
		}
		return v, v, nil
	}
	sPorts := strings.SplitN(s, `-`, 2)
	for i := range sPorts {
		sPorts[i] = strings.Trim(sPorts[i], " ")
	}
	if len(sPorts) != 2 || sPorts[0] == "" || sPorts[1] == "" {
		return notAPort, notAPort, fmt.Errorf("appears to be a range but could not be parsed; `%s`", s)
	}
	startPort, err := parsePortValueParseInt("beginning range ", sPorts[0])
	if err != nil {
		return notAPort, notAPort, err
	}
	endPort, err := parsePortValueParseInt("ending range ", sPorts[1])
	if err != nil {
		return notAPort, notAPort, err
	}
	if startPort == firewall.PortAny {
		endPort = firewall.PortAny
	}
	return startPort, endPort, nil
}

func parsePortValueParseInt(prefix, s string) (int32, error) {
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("%sout of range [0,65535]; `%s`", prefix, s)
		}
		return 0, fmt.Errorf("%swas not a number; `%s`", prefix, s)
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("%sout of range [0,65535]; `%s`", prefix, s)
	}
	return int32(n), nil
}

// --- parsePortManual: hand-rolled byte loop ---------------------------------

func parsePortManual(s string) (int32, int32, error) {
	const notAPort int32 = -2
	if s == "any" {
		return firewall.PortAny, firewall.PortAny, nil
	}
	if s == "fragment" {
		return firewall.PortFragment, firewall.PortFragment, nil
	}
	if !strings.Contains(s, `-`) {
		v, err := parsePortValueManual("", s)
		if err != nil {
			return notAPort, notAPort, err
		}
		return v, v, nil
	}
	sPorts := strings.SplitN(s, `-`, 2)
	for i := range sPorts {
		sPorts[i] = strings.Trim(sPorts[i], " ")
	}
	if len(sPorts) != 2 || sPorts[0] == "" || sPorts[1] == "" {
		return notAPort, notAPort, fmt.Errorf("appears to be a range but could not be parsed; `%s`", s)
	}
	startPort, err := parsePortValueManual("beginning range ", sPorts[0])
	if err != nil {
		return notAPort, notAPort, err
	}
	endPort, err := parsePortValueManual("ending range ", sPorts[1])
	if err != nil {
		return notAPort, notAPort, err
	}
	if startPort == firewall.PortAny {
		endPort = firewall.PortAny
	}
	return startPort, endPort, nil
}

func parsePortValueManual(prefix, s string) (int32, error) {
	if len(s) == 0 || len(s) > 5 {
		// >5 digits cannot represent a value <= 65535; <1 byte cannot be a port.
		if len(s) == 0 {
			return 0, fmt.Errorf("%swas not a number; `%s`", prefix, s)
		}
		// fall through to the per-byte check so genuinely-non-digit input
		// produces the "was not a number" diagnostic rather than "out of range".
	}
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%swas not a number; `%s`", prefix, s)
		}
		n = n*10 + uint32(c-'0')
		if n > 65535 {
			return 0, fmt.Errorf("%sout of range [0,65535]; `%s`", prefix, s)
		}
	}
	return int32(n), nil
}

// --- Comparison benchmarks --------------------------------------------------

// benchParsePortStart / End / Err are package-level sinks. Assigning the
// results of each parsePort call to package-level vars prevents the Go
// compiler from eliding the call as dead code (a real risk for pure
// functions whose results are otherwise unused) — the compiler must treat
// package vars as observed externally and emit the stores.
var (
	benchParsePortStart int32
	benchParsePortEnd   int32
	benchParsePortErr   error
)

func BenchmarkParsePort_ParseUint(b *testing.B) { benchParsePortVariant(b, parsePort) }
func BenchmarkParsePort_Atoi(b *testing.B)      { benchParsePortVariant(b, parsePortAtoi) }
func BenchmarkParsePort_ParseInt(b *testing.B)  { benchParsePortVariant(b, parsePortParseInt) }
func BenchmarkParsePort_Manual(b *testing.B)    { benchParsePortVariant(b, parsePortManual) }

func benchParsePortVariant(b *testing.B, fn func(string) (int32, int32, error)) {
	for _, tc := range parsePortBenchInputs {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var s, e int32
			var err error
			for i := 0; i < b.N; i++ {
				s, e, err = fn(tc.in)
			}
			// Publish to package-level sinks so the compiler cannot elide
			// the loop body. The reads inside b.Logf prevent it from
			// noticing that benchParsePort* are write-only across the test.
			benchParsePortStart, benchParsePortEnd, benchParsePortErr = s, e, err
			if testing.Verbose() {
				b.Logf("last result: start=%d end=%d err=%v",
					benchParsePortStart, benchParsePortEnd, benchParsePortErr)
			}
		})
	}
}
