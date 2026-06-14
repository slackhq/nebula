//go:build !linux

package pq

// DirIsVolatile is unsupported off linux; ok=false means "no
// conclusion" and the caller stays silent.
func DirIsVolatile(dir string) (volatile bool, ok bool) { return false, false }
