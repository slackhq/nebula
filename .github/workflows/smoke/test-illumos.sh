#!/bin/sh

# Cross-compiles every package's tests for illumos and runs them in the OmniOS VM behind the `omnios` ssh alias.
# Go ships no illumos toolchain, so the binaries are built here and each runs from its package directory for testdata.

set -e -x

cd "$(dirname "$0")/../../.."

OUT=build/illumos-tests
VMSRC=/tmp/nebula-src

# Tests the illumos port documents as not applying there
SKIP='TestConsumeInsidePacketSelfTrafficChecksum|TestNewAESGCM|TestRemovingTheGroupHandsTheSocketBack'

rm -rf "$OUT"
mkdir -p "$OUT"

: >"$OUT/manifest"
for pkg in $(go list ./...); do
    dir="${pkg#github.com/slackhq/nebula}"
    dir="${dir#/}"
    [ -n "$dir" ] || dir=.
    name="$(echo "$dir" | tr '/.' '__')"
    GOOS=illumos GOARCH=amd64 CGO_ENABLED=0 go test -c -o "$OUT/$name.test" "$pkg"
    if [ -f "$OUT/$name.test" ]; then
        echo "$name $dir" >>"$OUT/manifest"
    fi
done

ssh omnios "rm -rf $VMSRC"
rsync -a --exclude .git ./ "omnios:$VMSRC/"

ssh omnios "cd $VMSRC && fail=0; while read -r name dir; do
    echo \"=== \$dir\"
    (cd \"\$dir\" && $VMSRC/$OUT/\$name.test -test.skip '$SKIP') || fail=1
done <$OUT/manifest; exit \$fail"
