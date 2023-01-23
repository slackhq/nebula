//go:build !darwin && !dragonfly && !freebsd && !netbsd && !openbsd
// +build !darwin,!dragonfly,!freebsd,!netbsd,!openbsd

package nebula

const immediatelyForwardToSelf bool = false
