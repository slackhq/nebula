package checksum

// archImpls exposes every hand-written implementation on this architecture
// so the tests exercise them directly, independent of what the public
// Checksum dispatches to on the running CPU. Without this, running the
// suite on a non-AVX2 machine compared gvisor against itself and left the
// assembly untested — silently. available=false makes the test skip loudly
// instead.
var archImpls = []archImpl{
	{name: "avx2", fn: checksumAVX2, available: hasAVX2},
}
