# DPLPMTUD for Nebula — Design Options

## Problem

Nebula's TUN MTU defaults to 1300 bytes — a conservative value chosen to avoid fragmentation on most paths. But real-world path MTUs vary widely (1500 Ethernet, 1492 PPPoE, 1458 carrier WiFi, 8900+ jumbo frames on LAN). A static value means:

- **LAN/datacenter peers** leave ~6x bandwidth on the table for large transfers (1300 vs 8900+)
- **Constrained paths** (carrier WiFi, VPN-over-VPN) still hit black holes if 1300 + overhead > path MTU
- **Operators must manually tune** `tun.mtu` per-host or accept the lowest common denominator

RFC 8899 (DPLPMTUD) solves this by actively probing each peer's path to find the maximum usable packet size, without relying on ICMP PTB messages (which are often filtered or spoofed).

## Current State in Nebula

### Overhead Budget

| Layer                       | IPv4     | IPv6     |
| --------------------------- | -------- | -------- |
| IP header                   | 20 B     | 40 B     |
| UDP header                  | 8 B      | 8 B      |
| Nebula header               | 16 B     | 16 B     |
| AEAD tag (ChaCha20/AES-GCM) | 16 B     | 16 B     |
| **Total overhead**          | **60 B** | **80 B** |

So `PLPMTU_to_TUN_MTU = PLPMTU - overhead` (60 or 80 depending on outer IP version).

### Existing Probe Mechanism: Test Packets

Nebula already has a request/reply probe built in:

- **Type:** `header.Test` (type 4), subtypes `TestRequest` (0) / `TestReply` (1)
- **Sent by:** `connection_manager.go` every 5s when outbound traffic has no inbound reply
- **Payload:** Currently empty (`[]byte("")`) → 32-byte UDP payload (16 header + 16 AEAD tag)
- **Reply:** Responder decrypts, echoes payload back as `TestReply`
- **Authentication:** Fully encrypted + authenticated (requires established Noise session)
- **Acknowledgment tracking:** Implicit — `connectionManager.In(hostinfo)` marks inbound traffic

This is almost exactly the "acknowledged PL" probe mechanism RFC 8899 requires. The key adaptations needed:

1. **Pad probes to specific sizes** (currently always empty)
2. **Track probe size → ack correlation** (currently just marks "alive")
3. **Set DF bit on probe packets** (currently not set)

## RFC 8899 State Machine (Adapted for Nebula)

```
                   ┌──────────┐
           ┌───────│ DISABLED │
           │       └──────────┘
           │ tunnel established
           ▼
        ┌──────┐  probe BASE acked    ┌───────────┐
        │ BASE │─────────────────────▶│ SEARCHING │◀─┐
        └──────┘                      └───────────┘  │
           ▲  ▲                         │    │       │
           │  │ BASE probe succeeds     │    │       │ RAISE_TIMER
           │  │                         │    │       │
           │  ├──────────┐              │    │       │
           │  │  ┌───────┴┐             │    │       │
           │  │  │ ERROR  │             │    │       │
           │  │  └────────┘             │    │       │
           │  │   ▲  BASE probe fails   │    │       │
           │  │   │  after MAX_PROBES   │    │       │
           │  │   │                     │    │       │
           │  │   │ MAX_PROBES hit      │    │       │
           │  │   │ or MAX_PLPMTU       ▼    │       │
           │  │   │             ┌─────────────────┐  │
           │  └───┼─────────────│ SEARCH_COMPLETE │──┘
           │      │  black hole └─────────────────┘
           └──────┘
        black hole (to BASE)
```

**States:**

- **DISABLED:** No probing. Entered before tunnel establishment.
- **BASE:** Probing BASE_PLPMTU to confirm minimum path viability. Entry point after tunnel established.
- **SEARCHING:** Actively probing for larger PLPMTU. Entered from BASE on successful BASE probe.
- **SEARCH_COMPLETE:** PLPMTU found. Periodic confirmation probes. Re-enters SEARCHING on RAISE_TIMER.
- **ERROR:** Path cannot support BASE_PLPMTU. Uses ERROR_PLPMTU (1280) for data traffic. Periodically re-probes BASE every RAISE_TIMER (600s) — not PROBE_TIMER, since the path is known-degraded and aggressive probing wastes bandwidth. Entered from BASE when BASE probe fails after MAX_PROBES attempts. Exits to BASE when a BASE probe succeeds.

**Per-hostinfo state** (each tunnel gets its own PLPMTU):

```go
type plpmtud struct {
    state        plpmtudState  // DISABLED, BASE, SEARCHING, SEARCH_COMPLETE, ERROR
    plpmtu       int           // current validated PLPMTU (UDP payload size)
    probeSize    int           // size being probed
    probeCount   int           // consecutive failed probes at current size
    probeTimer   time.Time     // when current probe was sent
    raiseTimer   time.Time     // when to re-enter SEARCHING
    // Correlation: match echoed probe_size in TestProbeReply payload against probeSize
    lastRemote   netip.AddrPort // remote address when PLPMTU was last validated
}
```

## Design Options

### Option A: Extend Test Packets (Recommended)

Add a `TestProbe` / `TestProbeReply` subtype pair alongside the existing `TestRequest` / `TestReply`.

**Probe format:**

```
[16B Nebula header: Type=Test, Subtype=TestProbe]
[encrypted payload: 1B version | 2B probe_size (big-endian) | padding to target size]
[16B AEAD tag]
```

The `version` byte (initially 0) provides forward compatibility for Phase 4 relay-aware probing.

**Probe correlation:** The responder echoes the decrypted probe payload (version + probe_size, without padding) in the TestProbeReply. The sender correlates replies by matching the echoed `probe_size` against its outstanding `probeSize`. This works because Nebula's `MessageCounter` is per-sender (the responder uses its own counter in the reply header, not the probe's), so the header counter cannot be used for correlation. The reply payload is small (3 bytes) regardless of probe size.

**Why new subtypes?** Keeps the existing liveness-check Test packets untouched. PLPMTU probes have different semantics (loss is expected and must not trigger tunnel deletion).

**Advantages:**

- Minimal protocol change — reuses existing encrypt/decrypt/dispatch paths
- Already authenticated end-to-end (Noise session)
- Reply confirms the full probe was received and decrypted (not just IP-layer delivery)
- Connection manager already runs periodic timers per-hostinfo — natural place to drive the state machine
- Probe loss doesn't feed into congestion (Nebula has no congestion control)

**Implementation sketch:**

1. Add `header.TestProbe = 2`, `header.TestProbeReply = 3` subtypes
2. In `outside.go` `case header.Test` dispatch:
   - `TestProbe`: decrypt, reply with `TestProbeReply` echoing `version + probe_size` from the decrypted payload (3 bytes, no padding — reply is small regardless of probe size)
   - `TestProbeReply`: decrypt, extract echoed `probe_size`, call `hostinfo.plpmtud.handleProbeReply(probeSize)` to advance the state machine
3. Add `plpmtud` struct to `HostInfo`
4. Drive state machine from `connection_manager.go` timer loop
5. Set DF on probe sends via dedicated probe socket or socket option toggling (see DF Bit Handling)
6. Expose discovered per-peer PLPMTU via metrics and/or control socket

### Option B: Reuse Existing Test Packets with Size Marker

Instead of new subtypes, pad existing `TestRequest` packets and infer probe intent from payload size > 0.

**Advantages:** Zero protocol version change.
**Disadvantages:**

- Overloads liveness semantics with MTU probing — a lost PLPMTU probe could trigger `pendingDeletion` → tunnel teardown
- Old Nebula versions would waste bandwidth echoing large payloads they don't understand as probes
- Harder to distinguish "probe lost because path doesn't support size" from "probe lost because peer is down"

### Option C: New Message Type

Add `header.PLPMTUDProbe` as a new top-level message type (7).

**Advantages:** Cleanest separation of concerns.
**Disadvantages:** Slightly larger protocol surface. Old peers would log "unknown message type" warnings. Not worth it when Test subtypes achieve the same thing.

### Option D: Piggyback on Data Packets

Mark certain data packets as "MTU probes" by padding them to the target size. Track acknowledgment via the existing Noise message counter (the counter in the Nebula header is unique and monotonic).

**Advantages:** No extra packets — discovers MTU during normal traffic. Like QUIC's PADDING frame approach.
**Disadvantages:**

- Nebula has no ACK mechanism for data packets (it's a Layer 3 overlay, not a transport). The inner TCP/UDP handles reliability, but Nebula doesn't see those ACKs.
- Would need to add an explicit ACK mechanism for padded data, which is more invasive than probe packets.
- Padding real data risks black-holing application traffic during probing.

**Verdict:** Not viable without adding a data-plane ACK mechanism.

## Recommended Approach: Option A

### Overlay IPv6 Constraint

Nebula now supports IPv6 on the overlay (inside the tunnel), not just the underlay. IPv6 mandates a minimum link MTU of 1280 bytes (RFC 8200 §5). This means **the effective per-peer TUN MTU must never drop below 1280** when the overlay carries IPv6.

This creates a hard floor on PLPMTU:

```
min_tun_mtu  = 1280              (IPv6 overlay requirement)
min_plpmtu   = min_tun_mtu + overhead
             = 1280 + 60 = 1340  (IPv4 underlay)
             = 1280 + 80 = 1360  (IPv6 underlay)
```

If PLPMTUD probing discovers a path that can't sustain 1340/1360B, the overlay IPv6 minimum is violated. In this case Nebula should:

1. Log a warning that the path cannot support overlay IPv6 at minimum MTU
2. Fall into the RFC 8899 `ERROR` state
3. Continue operating at whatever size works — overlay IPv4 traffic still functions fine, and overlay IPv6 will rely on the inner stack's own PMTUD (which will see the small link MTU and adapt)

The `BASE_PLPMTU` must be set high enough to satisfy overlay IPv6 on **both** underlay types. Using 1360 unconditionally works: it's the IPv6-underlay floor and is well within typical IPv4 path MTUs (1500):

### Constants

| Constant             | Recommended Value         | Notes                                                                                                                                                                                                                                       |
| -------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BASE_PLPMTU`        | 1360 B                    | 1280 (overlay IPv6 min) + 80 (IPv6 underlay overhead). Using 1360 unconditionally works for both underlays: 1360 is well within IPv4's typical 1500-byte path MTU, and satisfies the IPv6 overlay floor on both underlay types.             |
| `MIN_PROBE_SIZE`     | 35 B                      | Minimum valid probe packet: 16 (header) + 3 (1B version + 2B probe_size) + 16 (AEAD tag) = 35 bytes UDP payload.                                                                                                                            |
| `ERROR_PLPMTU`       | 1280 B (v4) / 1280 B (v6) | Operational PLPMTU used in ERROR state when BASE_PLPMTU cannot be sustained. Yields TUN MTU of 1220 (v4) or 1200 (v6) — below the overlay IPv6 floor, but the best we can do. Overlay IPv4 still works; overlay IPv6 relies on inner PMTUD. |
| `OVERLAY_IPV6_FLOOR` | 1360 B                    | Hard floor when overlay IPv6 is in use. Equals BASE_PLPMTU, so BASE state already satisfies this.                                                                                                                                           |
| `MAX_PLPMTU`         | 9001 B                    | Buffer limit; capped by local interface MTU                                                                                                                                                                                                 |
| `MAX_PROBES`         | 3                         | Per RFC 8899 recommendation                                                                                                                                                                                                                 |
| `PROBE_TIMER`        | 15 s                      | Must be > RTT; 15s is RFC 8899 SHOULD                                                                                                                                                                                                       |
| `RAISE_TIMER`        | 600 s (10 min)            | Per RFC 8899; re-probe for larger MTU                                                                                                                                                                                                       |
| `PROBE_STEP`         | see search algorithm      | Binary search or table-based                                                                                                                                                                                                                |

### Search Algorithm

**Table-based with binary search fallback:**

```go
// Common PLPMTU sizes (UDP payload = wire MTU - IP+UDP headers).
// Sorted ascending. The search tries each in order; on failure, binary
// search between last-known-good and failed size.
var commonPLPMTUs = []int{
    // 1360 is BASE_PLPMTU — already confirmed before SEARCHING.
    // Search starts from the first entry > BASE_PLPMTU.
    1400,  // conservative (Nebula's current tun.mtu=1300 + ~60-80 overhead)
    1444,  // PPPoE IPv6 (1492 - 48)
    1452,  // Ethernet IPv6 (1500 - 48)
    1464,  // PPPoE IPv4 (1492 - 28)
    1472,  // Ethernet IPv4 (1500 - 28)
    2800,  // some cloud VPCs (GCP 1460 would be found by binary search 1472→2800)
    4500,  // mid-range jumbo (fills gap, keeps binary search ≤ 4 steps in 2800-8921)
    8921,  // jumbo frames IPv6 (9001 - 80)
    8941,  // jumbo frames IPv4 (9001 - 60)
}
```

Note: MAX_PLPMTU (9001) is the internal buffer size. These table entries are target probe sizes; the actual path maximum is discovered by probing. The table values are PLPMTU (UDP payload size), not wire MTU.

SEARCHING starts from the first table entry above BASE_PLPMTU. On success, advance to the next entry. On failure at a table entry, binary search between last-known-good and failed size. For common Ethernet/PPPoE paths, convergence is fast (3-5 probes). For jumbo-frame paths, the 4500 intermediate entry keeps worst-case binary search within the large gaps to ~4 additional steps.

### DF Bit Handling

**Critical requirement:** Probes MUST be sent with Don't Fragment set, otherwise the network will fragment them and the probe proves nothing.

| Platform     | Mechanism                                        | Notes                                                                                       |
| ------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Linux        | `setsockopt(IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)` | Per-socket. Sets DF and suppresses kernel PMTUD processing (no kernel PTB cache updates).   |
| Darwin/macOS | `setsockopt(IP_DONTFRAG, 1)`                     | Per-socket.                                                                                 |
| FreeBSD      | `setsockopt(IP_DONTFRAG, 1)`                     | Per-socket.                                                                                 |
| Windows      | `setsockopt(IP_DONTFRAGMENT, 1)`                 | Per-socket.                                                                                 |
| IPv6 (all)   | `setsockopt(IPV6_DONTFRAG, 1)`                   | Per-socket. IPv6 never fragments at routers anyway, but this prevents sender fragmentation. |

**All of these are per-socket options, not per-packet.** There is no portable per-packet DF mechanism on Linux (sendmsg ancillary data does not support DF).

For non-probe packets, DF should remain **unset** (current behavior) so the network can fragment if needed. Options:

1. **Toggle socket option around probe sends (recommended).** Each Nebula routine has its own UDP socket (`f.writers[q]`). Set `IP_PMTUDISC_PROBE` before the probe send, restore `IP_PMTUDISC_DONT` after. **Important:** `ci.writeLock` is only held in BoringCrypto builds and is per-ConnectionState, not per-socket. Multiple tunnels share the same `writers[q]` socket, so a **per-writer mutex** (`writers[q].dfLock`) is needed to serialize setsockopt+sendmsg atomically. Since PLPMTUD runs from the single connection manager goroutine, it can use the appropriate `writers[q]` for the hostinfo's routine assignment. No NAT issues since probes use the same socket/port as normal traffic.

2. **Dedicated probe UDP socket.** Simplest implementation, but **probes arrive from a different source port**, which breaks strict NAT / stateful firewalls that only allow traffic matching the established 5-tuple. PLPMTUD would silently fail on these paths (probes dropped, stuck at BASE_PLPMTU forever). Not recommended unless NAT traversal is explicitly out of scope.

3. **Always-DF on all traffic.** Set `IP_PMTUDISC_PROBE` once at socket creation. Simplest, but risks black-holing all data traffic if PLPMTUD has a bug. Consider as a future option once PLPMTUD is proven stable.

### Integration with Connection Manager

The PLPMTUD state machine runs alongside (not inside) the existing connection manager's traffic decision loop:

```
Every checkInterval (5s):
  for each hostinfo:
    // existing liveness check — returns a trafficDecision (unchanged)
    doTrafficCheck(hostinfo)

    // PLPMTUD state machine — runs unconditionally, independent of trafficDecision
    // This requires refactoring makeTrafficDecision so it is not the sole
    // action driver. PLPMTUD checks run after the traffic decision is executed.
    if hostinfo.plpmtud.state != DISABLED:
      doPLPMTUDCheck(hostinfo)
```

**Note:** The current `makeTrafficDecision` returns a single `trafficDecision` enum. PLPMTUD must run as a separate action after the traffic decision, not as an alternative to it. This is a minor refactor — `doPLPMTUDCheck` sends its own probe packet independently of whatever `doTrafficCheck` decided (sendTestPacket, sendPunch, etc.).

**Buffer allocation:** The connection manager's `Start()` pre-allocates `p := []byte("")` and `out := make([]byte, mtu)` (9001). PLPMTUD probes need a large payload buffer (up to MAX_PLPMTU - 32 bytes = 8969 bytes of padding). Pre-allocate a dedicated `probePayload []byte` in `Start()` alongside `p` and `out`. Since the connection manager is a single goroutine, no synchronization is needed for this buffer.

State transitions on probe ack/timeout would be driven by:

- **Probe sent:** Record `probeSize`, start `probeTimer`
- **TestProbeReply received:** Match echoed `probe_size` from reply payload against outstanding `probeSize`, advance state machine
- **Timer expiry:** Increment `probeCount`, retry or transition

### Interaction with tun.mtu

Two modes:

**Mode 1: Per-peer MTU (recommended initial implementation)**

- Keep `tun.mtu` as the TUN device MTU (unchanged)
- PLPMTUD sets a per-hostinfo effective MTU
- On `inside.go` send path, clamp packet size to `min(tun.mtu, hostinfo.plpmtu - overhead)`
- If inner packet exceeds peer's PLPMTU, generate ICMP Fragmentation Needed back into the TUN (enables inner path MTU discovery)

**Mode 2: Dynamic TUN MTU**

- Adjust TUN device MTU to the maximum discovered PLPMTU across all active peers
- More complex; requires re-notifying the OS, and the TUN MTU is shared across all peers
- Better left as a future optimization

### PTB Message Integration (Optional Enhancement)

RFC 8899 allows using ICMP PTB messages as hints (not gospel):

- If Nebula receives an ICMP "Fragmentation Needed" / "Packet Too Big" for its outer UDP packets, it can use the indicated MTU as a search hint
- PTB messages MUST be validated (match 5-tuple from quoted packet)
- PTB-indicated size is never trusted to _increase_ PLPMTU — only to suggest a lower search target
- This is an optimization, not a requirement. Probing alone is sufficient.

### Black Hole Detection

When in `SEARCH_COMPLETE`, periodically confirm the current PLPMTU still works:

- SEARCH_COMPLETE uses **two timers with different purposes:**
  - **PROBE_TIMER (15s):** Confirmation probes at the current PLPMTU for black hole detection. If `MAX_PROBES` (3) consecutive confirmation probes fail → fall back to `BASE` state. Detection time: ~45s.
  - **RAISE_TIMER (600s):** After this period, re-enter SEARCHING to try discovering a larger PLPMTU (path may have improved).
- This catches path changes (re-routing through a lower-MTU link)

**Important:** PLPMTU probe failures (TestProbe timeout) must NOT trigger the connection manager's `pendingDeletion` / tunnel teardown logic. Probe loss means "this size doesn't fit," not "peer is down." The existing liveness `TestRequest` / `TestReply` mechanism continues to run independently for tunnel health.

**Recovery time:** On a path MTU decrease (e.g., 8941 → 1472), worst case is 3 failed confirmation probes (45s) then search back up from BASE (1360). Total recovery: ~2 minutes. This matches RFC 8899's design — the BASE fallback is intentionally conservative. A future optimization could bisect downward on black hole detection rather than falling all the way to BASE.

### Configuration

```yaml
# New config section
tun:
  mtu: 1300 # existing; becomes the "floor" / static fallback
  plpmtud:
    enabled: true # default: false initially, true once stable
    base_plpmtu: 1360 # default: 1360 (supports overlay IPv6 on both underlay types)
    max_plpmtu: 8941 # default: 8941 (buffer limit 9001 - 60 IPv4 overhead)
    probe_interval: 15s # PROBE_TIMER
    raise_interval: 600s # RAISE_TIMER
    max_probes: 3 # MAX_PROBES
```

## Implementation Phases

### Phase 1: Core Probe Mechanism + MTU Enforcement

- Add `TestProbe` / `TestProbeReply` subtypes
- Implement padded probe send + reply in `outside.go`
- DF bit on probe packets (Linux first, then other platforms)
- Per-hostinfo `plpmtud` state struct
- State machine in `connection_manager.go`
- Metrics: `plpmtud.discovered_mtu` gauge per peer
- **MTU enforcement in `inside.go`:** If inner packet exceeds peer's discovered PLPMTU minus overhead, **drop the packet** and generate ICMP back into TUN: **ICMP Fragmentation Needed** (Type 3, Code 4) for IPv4 inner packets, **ICMPv6 Packet Too Big** (Type 2) for IPv6 inner packets. Both must include the discovered per-peer TUN MTU. Nebula does not perform IP fragmentation at the overlay layer. This must ship with Phase 1 — without it, discovered PLPMTU values are useless and oversized traffic is silently black-holed.

### Phase 2: Optimizations and Robustness

- Per-route MTU interaction (take the min of route MTU and discovered PLPMTU)

- PTB message integration as search hints
- Piggyback confirmation probes on liveness Test packets in `SEARCH_COMPLETE`
- Config hot-reload support

### Phase 3: Advanced

- Relay-aware PLPMTUD (probe through relay paths separately)
- Dynamic TUN MTU adjustment (Mode 2)
- PLPMTU sharing via lighthouse (cache discovered MTUs for known paths)

## Comparison with QUIC's Approach

| Aspect                 | QUIC (RFC 9000)           | Nebula (proposed)           |
| ---------------------- | ------------------------- | --------------------------- |
| Probe mechanism        | PING + PADDING frames     | TestProbe + padding         |
| Acknowledgment         | ACK frames (built-in)     | TestProbeReply (built-in)   |
| Congestion interaction | Probes consume cwnd       | N/A (no congestion control) |
| BASE_PLPMTU            | 1200 B                    | 1360 B                      |
| DF bit                 | Always set (QUIC mandate) | Set on probes only          |
| Per-connection         | Yes                       | Yes (per-hostinfo)          |
| Encryption             | Full AEAD                 | Full AEAD (Noise)           |

Nebula's situation is actually simpler than QUIC's because:

1. No congestion control to interact with
2. Existing Test packet mechanism is a near-perfect fit
3. Tunnels are long-lived (worth amortizing probe cost)
4. The connection manager already runs per-peer timers

## Open Questions

1. **Should non-probe packets also set DF?** Currently they don't, meaning the network can fragment Nebula's outer UDP packets. Setting DF everywhere would force all traffic through the discovered PLPMTU but risks black-holing if PLPMTUD has a bug. Conservative approach: DF on probes only initially.

2. **Relay paths:** A relayed tunnel has a different path MTU than a direct tunnel. Should PLPMTUD probe through relays separately? Probably yes (Phase 4).

3. **Backwards compatibility:** Old peers will see `TestProbe` as an unknown Test subtype. Current `outside.go` only checks `h.Subtype == header.TestRequest` — unknown subtypes fall through without sending a reply, but the old peer **will still decrypt and authenticate the full probe payload** (consuming CPU and bandwidth for large probes) and call `connectionManager.In(hostinfo)` (marking liveness). The probe will time out (no TestProbeReply) and PLPMTUD will stay at BASE_PLPMTU. This is safe (no crash, no tunnel disruption), but wasteful in mixed-version fleets. Mitigation: after 3 consecutive probe timeouts without any TestProbeReply from a peer, back off PLPMTUD for that hostinfo — retry a single probe after RAISE_TIMER (10 min), doubling the backoff on each failure up to 1 hour max. This handles rolling upgrades: when the peer upgrades mid-tunnel, it will be discovered within one backoff period.

4. **Multiple paths / roaming:** A peer may be reachable via multiple remote addresses (roaming). The `plpmtud` struct tracks `lastRemote` — on roam detection (remote address change via `handleHostRoaming`), immediately reset PLPMTUD to BASE state and re-probe. This avoids up to 45 seconds of black-holed traffic if the new path has a lower MTU than the old one.

5. **Initial probe timing:** Should PLPMTUD start probing immediately after handshake, or wait for data traffic? Immediate probing means faster MTU discovery but adds packets to a freshly established tunnel. A short delay (e.g., 1s after handshake) is probably fine.

6. **Overlay IPv6 floor enforcement:** When the overlay carries IPv6, the per-peer TUN MTU can't go below 1280. If a path can't sustain 1340B (IPv4 underlay) or 1360B (IPv6 underlay), what should happen? Options: (a) stay in ERROR state and let inner IPv6 PMTUD adapt, (b) disable overlay IPv6 for that peer, (c) enable Nebula-layer fragmentation as a fallback (significant complexity). Option (a) is simplest but means overlay IPv6 packets > path MTU will be black-holed until the inner stack discovers the reduced MTU via its own PMTUD.
