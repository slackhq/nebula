package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
	"go.yaml.in/yaml/v3"
)

type m = map[string]any

func Main(c *config.C, configTest bool, buildVersion string, l *slog.Logger, deviceFactory overlay.DeviceFactory) (retcon *Control, reterr error) {
	ctx, cancel := context.WithCancel(context.Background())
	// Automatically cancel the context if Main returns an error, to signal all created goroutines to quit.
	defer func() {
		if reterr != nil {
			cancel()
		}
	}()

	if buildVersion == "" {
		buildVersion = moduleVersion()
	}

	// Print the config if in test, the exit comes later
	if configTest {
		b, err := yaml.Marshal(c.Settings)
		if err != nil {
			return nil, err
		}

		// Print the final config
		l.Info(string(b))
	}

	pki, err := NewPKIFromConfig(l, c)
	if err != nil {
		return nil, util.ContextualizeIfNeeded("Failed to load PKI from config", err)
	}

	fw, err := NewFirewallFromConfig(l, pki.getCertState(), c)
	if err != nil {
		return nil, util.ContextualizeIfNeeded("Error while loading firewall rules", err)
	}
	l.Info("Firewall started", "firewallHashes", fw.GetRuleHashes())

	ssh, err := sshd.NewSSHServer(ctx, l.With("subsystem", "sshd"))
	if err != nil {
		return nil, util.ContextualizeIfNeeded("Error while creating SSH server", err)
	}
	wireSSHReload(l, ssh, c)
	var sshStart func()
	if c.GetBool("sshd.enabled", false) {
		sshStart, err = configSSH(l, ssh, c)
		if err != nil {
			l.Warn("Failed to configure sshd, ssh debugging will not be available", "error", err)
			sshStart = nil
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// All non system modifying configuration consumption should live above this line
	// tun config, listeners, anything modifying the computer should be below
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	var routines int

	// If `routines` is set, use that and ignore the specific values
	if routines = c.GetInt("routines", 0); routines != 0 {
		if routines < 1 {
			routines = 1
		}
		if routines > 1 {
			l.Info("Using multiple routines", "routines", routines)
		}
	} else {
		// deprecated and undocumented
		tunQueues := c.GetInt("tun.routines", 1)
		udpQueues := c.GetInt("listen.routines", 1)
		routines = max(tunQueues, udpQueues)
		if routines != 1 {
			l.Warn("Setting tun.routines and listen.routines is deprecated. Use `routines` instead", "routines", routines)
		}
	}

	// EXPERIMENTAL
	// Intentionally not documented yet while we do more testing and determine
	// a good default value.
	conntrackCacheTimeout := c.GetDuration("firewall.conntrack.routine_cache_timeout", 0)
	if routines > 1 && !c.IsSet("firewall.conntrack.routine_cache_timeout") {
		// Use a different default if we are running with multiple routines
		conntrackCacheTimeout = 1 * time.Second
	}
	if conntrackCacheTimeout > 0 {
		l.Info("Using routine-local conntrack cache", "duration", conntrackCacheTimeout)
	}

	var tun overlay.Device
	if !configTest {
		c.CatchHUP(ctx)

		if deviceFactory == nil {
			deviceFactory = overlay.NewDeviceFromConfig
		}

		tun, err = deviceFactory(c, l, pki.getCertState().myVpnNetworks, routines)
		if err != nil {
			return nil, util.ContextualizeIfNeeded("Failed to get a tun/tap device", err)
		}

		defer func() {
			if reterr != nil {
				tun.Close()
			}
		}()
	}

	// set up our UDP listener
	udpConns := make([]udp.Conn, routines)
	port := c.GetInt("listen.port", 0)

	// Callers get no handle to these until the Control is returned, release them on any error.
	defer func() {
		if reterr != nil {
			for _, u := range udpConns {
				if u != nil {
					_ = u.Close()
				}
			}
		}
	}()

	if !configTest {
		rawListenHost := c.GetString("listen.host", "0.0.0.0")
		var listenHost netip.Addr
		if rawListenHost == "[::]" {
			// Old guidance was to provide the literal `[::]` in `listen.host` but that won't resolve.
			listenHost = netip.IPv6Unspecified()

		} else {
			ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", rawListenHost)
			if err != nil {
				return nil, util.ContextualizeIfNeeded("Failed to resolve listen.host", err)
			}
			if len(ips) == 0 {
				return nil, util.ContextualizeIfNeeded("Failed to resolve listen.host", err)
			}
			listenHost = ips[0].Unmap()
		}

		for i := 0; i < routines; i++ {
			l.Info("listening", "addr", netip.AddrPortFrom(listenHost, uint16(port)))
			udpServer, err := udp.NewListener(l, listenHost, port, routines > 1, c.GetInt("listen.batch", 64))
			if err != nil {
				return nil, util.NewContextualError("Failed to open udp listener", m{"queue": i}, err)
			}
			udpServer.ReloadConfig(c)
			udpConns[i] = udpServer

			// If port is dynamic, discover it before the next pass through the for loop
			// This way all routines will use the same port correctly
			if port == 0 {
				uPort, err := udpServer.LocalAddr()
				if err != nil {
					return nil, util.NewContextualError("Failed to get listening port", nil, err)
				}
				port = int(uPort.Port())
			}
		}
	}

	hostMap := NewHostMapFromConfig(l, c)
	punchy := NewPunchyFromConfig(l, c, udpConns[0])
	connManager := newConnectionManagerFromConfig(l, c, hostMap, punchy)
	lightHouse, err := NewLightHouseFromConfig(ctx, l, c, pki.getCertState(), udpConns[0], punchy)
	if err != nil {
		return nil, util.ContextualizeIfNeeded("Failed to initialize lighthouse handler", err)
	}

	var messageMetrics *MessageMetrics
	if c.GetBool("stats.message_metrics", false) {
		messageMetrics = newMessageMetrics()
	} else {
		messageMetrics = newMessageMetricsOnlyRecvError()
	}

	handshakeConfig := HandshakeConfig{
		tryInterval:    c.GetDuration("handshakes.try_interval", DefaultHandshakeTryInterval),
		retries:        int64(c.GetInt("handshakes.retries", DefaultHandshakeRetries)),
		triggerBuffer:  c.GetInt("handshakes.trigger_buffer", DefaultHandshakeTriggerBuffer),
		messageMetrics: messageMetrics,
	}

	handshakeManager := NewHandshakeManager(l, hostMap, lightHouse, udpConns[0], handshakeConfig)
	lightHouse.handshakeTrigger = handshakeManager.trigger

	ds, err := newDnsServerFromConfig(ctx, l, pki, hostMap, c)
	if err != nil {
		l.Warn("Failed to start DNS responder", "error", err)
	}

	ifConfig := &InterfaceConfig{
		HostMap:               hostMap,
		Inside:                tun,
		Outside:               udpConns[0],
		pki:                   pki,
		Firewall:              fw,
		DnsServer:             ds,
		HandshakeManager:      handshakeManager,
		connectionManager:     connManager,
		lightHouse:            lightHouse,
		tryPromoteEvery:       c.GetUint32("counters.try_promote", defaultPromoteEvery),
		reQueryEvery:          c.GetUint32("counters.requery_every_packets", defaultReQueryEvery),
		reQueryWait:           c.GetDuration("timers.requery_wait_duration", defaultReQueryWait),
		DropLocalBroadcast:    c.GetBool("tun.drop_local_broadcast", false),
		DropMulticast:         c.GetBool("tun.drop_multicast", false),
		routines:              routines,
		MessageMetrics:        messageMetrics,
		version:               buildVersion,
		relayManager:          NewRelayManager(ctx, l, hostMap, c),
		punchy:                punchy,
		ConntrackCacheTimeout: conntrackCacheTimeout,
		CpuAffinity:           parseCpuAffinity(c, l, routines),
		l:                     l,
	}

	var ifce *Interface
	if !configTest {
		ifce, err = NewInterface(ctx, ifConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize interface: %s", err)
		}

		ifce.writers = udpConns
		lightHouse.ifce = ifce

		ifce.RegisterConfigChangeCallbacks(c)
		ifce.reloadDisconnectInvalid(c)
		ifce.reloadSendRecvError(c)
		ifce.reloadAcceptRecvError(c)
		ifce.reloadEcn(c)

		handshakeManager.f = ifce
		go handshakeManager.Run(ctx)

		punchy.Start(ctx, ifce, hostMap, lightHouse)
	}

	stats, err := newStatsServerFromConfig(ctx, l, c, buildVersion, configTest)
	if err != nil {
		return nil, util.ContextualizeIfNeeded("Failed to start stats emitter", err)
	}

	if configTest {
		return nil, nil
	}

	go ifce.emitStats(ctx, c.GetDuration("stats.interval", time.Second*10))

	attachCommands(l, c, ssh, ifce)

	return &Control{
		state:                  StateReady,
		f:                      ifce,
		l:                      l,
		ctx:                    ctx,
		cancel:                 cancel,
		sshStart:               sshStart,
		statsStart:             stats.Start,
		dnsStart:               ds.Start,
		lighthouseStart:        lightHouse.StartUpdateWorker,
		connectionManagerStart: connManager.Start,
	}, nil
}

// parseCpuAffinity reads `tun.cpu_affinity` from the config — a list of
// integer CPU IDs, one per TUN reader goroutine. Empty / unset returns nil
// (listenIn falls back to its default `i % NumCPU` pinning). Length
// mismatch with `routines` is a warning, not an error: shorter lists are
// modulo-cycled across queues, longer lists' tail is ignored. Invalid
// entries (non-integer, out of range) are also a warning and disable the
// override entirely so we don't silently pin to the wrong CPU.
func parseCpuAffinity(c *config.C, l *slog.Logger, routines int) []int {
	raw := c.Get("tun.cpu_affinity")
	if raw == nil {
		return nil
	}
	rv, ok := raw.([]any)
	if !ok {
		l.Warn("tun.cpu_affinity must be a list of integers; ignoring", "value", raw)
		return nil
	}
	nCPU := runtime.NumCPU()
	cpus := make([]int, 0, len(rv))
	for i, e := range rv {
		var cpu int
		switch v := e.(type) {
		case int:
			cpu = v
		case int64:
			cpu = int(v)
		case float64:
			cpu = int(v)
		default:
			l.Warn("tun.cpu_affinity entry not an integer; ignoring affinity",
				"index", i, "value", e)
			return nil
		}
		if cpu < 0 || cpu >= nCPU {
			l.Warn("tun.cpu_affinity entry out of range; ignoring affinity",
				"index", i, "cpu", cpu, "num_cpu", nCPU)
			return nil
		}
		cpus = append(cpus, cpu)
	}
	if len(cpus) != routines {
		l.Warn("tun.cpu_affinity length doesn't match routines; queues will modulo-cycle through the list",
			"affinity_len", len(cpus), "routines", routines)
	}
	return cpus
}

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	for _, dep := range info.Deps {
		if dep.Path == "github.com/slackhq/nebula" {
			return strings.TrimPrefix(dep.Version, "v")
		}
	}

	return ""
}
