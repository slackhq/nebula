//go:build linux

package pq

import "testing"

func TestIsVolatileFSType(t *testing.T) {
	if !isVolatileFSType(tmpfsMagic) || !isVolatileFSType(ramfsMagic) {
		t.Fatal("tmpfs/ramfs must classify volatile")
	}
	if isVolatileFSType(0xEF53) { // EXT4_SUPER_MAGIC
		t.Fatal("ext4 must not classify volatile")
	}
	// Regression: on 32-bit kernels st.Type is int32, so ramfs magic
	// (0x858458f6) is negative when stored as int32. A direct uint64
	// conversion sign-extends to 0xFFFFFFFF858458f6 and misses the
	// match without masking. The & 0xFFFFFFFF in DirIsVolatile must
	// retain only the low 32 bits.
	var ramfsAsInt32 int32 = -2054924042 // == int32(ramfsMagic)
	if !isVolatileFSType(uint64(ramfsAsInt32) & 0xFFFFFFFF) {
		t.Fatal("ramfs magic via sign-extended int32 must classify volatile")
	}
}

func TestDirIsVolatileDoesNotError(t *testing.T) {
	// Smoke: must return ok=true for an existing dir regardless of
	// which fs the CI runner mounts for TempDir.
	if _, ok := DirIsVolatile(t.TempDir()); !ok {
		t.Fatal("statfs on an existing dir must succeed")
	}
	if _, ok := DirIsVolatile("/nonexistent-path-zzz"); ok {
		t.Fatal("statfs on a missing dir must report ok=false")
	}
}
