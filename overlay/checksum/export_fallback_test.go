//go:build !amd64 && !arm64

package checksum

// No hand-written implementations on this architecture; the dispatcher is
// pure gvisor and there is nothing separate to test.
var archImpls []archImpl
