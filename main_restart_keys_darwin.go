//go:build darwin && !ios && !e2e_testing

package nebula

// osStartupOnlyKeys are startup only keys that only matter on macOS, the only OS that watches for network changes
var osStartupOnlyKeys = []string{"listen.rebind_on_network_change"}
