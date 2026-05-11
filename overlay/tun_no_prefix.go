//go:build (!darwin && !ios && !freebsd && !openbsd && !netbsd) || e2e_testing

package overlay

// StampTunPrefix is a no-op on platforms whose tun devices have no
// protocol-family marker. WireBuffer only invokes it when its prefixLen
// is non-zero, so this should never be reached on these platforms.
func StampTunPrefix(buf []byte) error {
	return nil
}
