//go:build !unix

package pq

import (
	"fmt"
	"os"
)

// openPSKFileNoFollow is a best-effort fallback for platforms (eg
// Windows) where syscall.O_NOFOLLOW is not available. We Lstat
// first to reject reparse points / symlinks, then open by the
// same path. A TOCTOU window remains between Lstat and Open: on
// Windows this is mitigated in practice by ACLing the PSK
// directory so untrusted principals cannot create reparse points
// inside it. Production-grade nebula deployments live on unix.
func openPSKFileNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("pq: refusing to open non-regular file %q (mode=%v)", path, fi.Mode())
	}
	return os.Open(path)
}
