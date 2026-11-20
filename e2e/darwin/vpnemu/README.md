# vpnemu

Reproduces, on macOS and without Tailscale, the way a VPN with an exit node takes nebula's vpn network route
away from its utun (#1931).

A macOS network extension never touches the routing table. Its routes are published in configd's dynamic store
under `State:/Network/Service/<id>/IPv4` and `/IPv6`, and configd's IPMonitor installs them. vpnemu creates a
utun and publishes those keys itself, so configd does exactly what it would do for the real app. It publishes
the routes Tailscale would with an exit node: every interface prefix that isn't a single IP, the rule in
Tailscale's `ipnlocal.internalAndExternalInterfacesFrom`.

| mode | Tailscale setting | published as | where nebula's prefix goes |
| --- | --- | --- | --- |
| `claim` | exit node, no LAN access | `AdditionalRoutes` | into vpnemu's utun |
| `exclude` | exit node, LAN access | `ExcludedRoutes`, service overrides primary | out the next interface (en0) |

configd answers `EEXIST` with a delete and an add, so whatever held the prefix loses it. When the service is
withdrawn, configd deletes its routes by prefix alone, whoever holds them by then.

## Build

It is its own module, so `purego` stays out of nebula's `go.mod`. purego reaches CoreFoundation and
SystemConfiguration without cgo, so it cross compiles and runs on a mac with no developer tools.

```sh
cd e2e/darwin/vpnemu
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o vpnemu .
# a cross compiled binary copied to a mac may need: codesign -s - -f vpnemu
```

## Run

```sh
sudo ./vpnemu -mode claim -keep en0      # runs until ctrl-c, then withdraws and closes its utun
sudo ./vpnemu -clear                     # withdraw a service a crashed run left behind
```

`-keep` names interfaces whose prefixes are never published. Keep the one your ssh session arrives on, or
`claim` takes your LAN into a utun nobody reads. `exclude` makes vpnemu primary, so anything off a kept
interface's subnet, internet included, goes into its utun and is dropped while it runs.

`-follow` (default on) republishes when interface prefixes change, as Tailscale does on link changes. With
`-follow=false` a route stays published after its interface is gone, which stages the route configd leaves
behind for a nebula that restarts before the VPN has caught up.

## A/B a nebula build

`repro.sh` starts nebula, then runs vpnemu, and reports egress and ping per peer before, during and after:

```sh
sudo ./repro.sh -n ./nebula -c config.yml -p 192.168.212.1 -p fd19:31::1 -m claim -k en0
```

Before #1931 (utun holds `/24` and `/64`):

```
during   192.168.212.1   egress=utun2   ping=FAIL
after    192.168.212.1   egress=en0     ping=FAIL
```

With #1931 (utun holds `/32` and `/128`, network routes added explicitly) every phase stays on nebula's utun.

### Leftover route

Run an old nebula, start `vpnemu -follow=false`, then restart onto a new nebula while vpnemu is still up. The
new nebula finds the vpn network routed to vpnemu's utun, replaces it and starts. Stop vpnemu and configd deletes
the prefix, taking nebula's route with it until nebula restarts. With real Tailscale this needs nebula to restart
before Tailscale notices the old utun is gone, a one time window when upgrading from a nebula without #1931.
