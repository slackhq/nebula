//go:build !race && !e2e_testing

package udp

// raceEnabled reports a -race build, whose sync.Pool drops a random share of what is put back.
const raceEnabled = false
