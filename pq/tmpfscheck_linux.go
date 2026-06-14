//go:build linux

package pq

import "golang.org/x/sys/unix"

// Magic numbers from linux/magic.h, declared locally as untyped constants
// so the uint64 width-masking comparison below stays explicit about the
// 32-bit kernel field.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// DirIsVolatile reports whether dir lives on a memory-backed
// filesystem (tmpfs/ramfs), where PSK files vanish on power-off.
// ok=false means the check itself failed (statfs error) and no
// conclusion should be drawn.
func DirIsVolatile(dir string) (volatile bool, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, false
	}
	// st.Type is int32 on 32-bit linux and int64 on 64-bit. Go uint64
	// conversion of a negative value sign-extends, so mask to the
	// kernel's 32-bit magic width explicitly: ramfs's magic overflows
	// int32 and would otherwise never match on 386/arm.
	return isVolatileFSType(uint64(st.Type) & 0xFFFFFFFF), true
}

func isVolatileFSType(t uint64) bool {
	return t == tmpfsMagic || t == ramfsMagic
}
