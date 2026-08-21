package checksum

// archImpls exposes every hand-written implementation on this architecture
// for direct testing; see export_amd64_test.go for the rationale. NEON is
// mandatory in armv8, so it is always available.
var archImpls = []archImpl{
	{name: "neon", fn: checksumNEON, available: true},
}
