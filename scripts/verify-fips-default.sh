#!/bin/sh
# Verifies that a Nebula build (built with the Makefile's GOENV and LDFLAGS):
#   1. Links a Go Cryptographic Module (GOFIPS140 build setting present)
#   2. Defaults GODEBUG=fips140 to off
#   3. Honors GODEBUG=fips140=on/off at runtime
#
# Catches regressions if the Makefile loses GOFIPS140 from GOENV or
# -X runtime.godebugDefault=fips140=off from LDFLAGS, or if a future Go
# release silently breaks the linker symbol we set.
#
# Invoked as: GOENV=... LDFLAGS=... sh scripts/verify-fips-default.sh

set -e

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/check.go" <<'EOF'
package main

import (
	"crypto/fips140"
	"fmt"
	"runtime/debug"
)

func main() {
	info, _ := debug.ReadBuildInfo()
	var module string
	for _, s := range info.Settings {
		if s.Key == "GOFIPS140" {
			module = s.Value
		}
	}
	fmt.Printf("enabled=%v module=%s\n", fips140.Enabled(), module)
}
EOF

# shellcheck disable=SC2086
env $GOENV go build -ldflags "$LDFLAGS" -o "$TMP/check" "$TMP/check.go"

assert() {
	want_enabled=$1
	label=$2
	shift 2
	got=$(env "$@" "$TMP/check")
	case "$got" in
	*"enabled=$want_enabled module=v"*) ;;
	*"enabled=$want_enabled module="*"-"*) ;;
	*"enabled=$want_enabled "*)
		echo "FAIL: $label: GOFIPS140 module not linked (output: $got)" >&2
		exit 1
		;;
	*)
		echo "FAIL: $label: expected fips140.Enabled()=$want_enabled (output: $got)" >&2
		exit 1
		;;
	esac
}

assert false "default invocation"
assert true  "GODEBUG=fips140=on"          GODEBUG=fips140=on
assert false "GODEBUG=fips140=off"         GODEBUG=fips140=off
assert false "GODEBUG with unrelated key"  GODEBUG=foo=bar

echo "OK: fips140 defaults to off; GODEBUG=fips140=on overrides; module is linked"
