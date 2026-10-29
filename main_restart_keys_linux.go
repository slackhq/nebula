//go:build linux && !android && !e2e_testing

package nebula

// osStartupOnlyKeys are startup only keys that only matter on linux: udp batch size, udp offloads and thread pinning
var osStartupOnlyKeys = []string{"listen.batch", "listen.udp_offloads", "tun.pin_threads", "tun.pin_threads_key", "tun.cpu_affinity"}
