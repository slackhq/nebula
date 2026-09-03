# Multiport lanes

Status: experimental. Linux only. Off unless `multiport.ports` is set.

## The problem

A nebula tunnel is one UDP 4-tuple. Everything between the two hosts that makes
a decision per flow makes it once, for the whole tunnel:

- **ECMP / LAG** hashes the 4-tuple and picks one path. A tunnel gets one path's
  worth of bandwidth no matter how many exist.
- **NIC RSS** hashes the 4-tuple to one receive queue, so one CPU takes every
  interrupt for the tunnel and receive is capped by a single core.
- **Per-flow policers and shapers** see one flow and rate-limit it as one.
- **Cloud per-flow bandwidth caps** are the hard version of that. AWS EC2 meters
  each 5-tuple separately and caps a single flow well below what the instance can
  do in aggregate -- on the order of 5 Gbps for a single flow within a VPC (more
  inside a cluster placement group, or with ENA Express; check the current EC2
  network-limits docs for exact numbers) on instances whose aggregate allowance
  is many times that. Other providers do the same. Nothing about the path is
  saturated when this fires, and no amount of retuning changes it: the hypervisor
  is metering *the flow*, so the only way to get more is to be more than one
  flow.

Running `routines: N` does not help. Those N sockets share one port through
`SO_REUSEPORT`, and the group is keyed on the exact `(addr, port)` pair, so the
kernel's reuseport hash is the *only* thing spreading the work -- every hash
outside this host still sees a single flow.

Multiport gives one tunnel several underlay 4-tuples, so all of those per-flow
decisions get made several times, independently. A tunnel with N lanes is N
flows to everything counting flows: N ECMP hashes, N receive queues, N of the
cloud provider's per-flow buckets.

There is a second bottleneck, and it is inside this host rather than out on the
network: in FIPS 140 mode the AES-GCM implementation refuses to seal twice under
the same nonce, which forces every encrypt on a session to be serialized behind
one mutex. `routines: N` does not help there either. Because each lane is a
separate session, multiport splits that mutex as well -- see
[The FIPS 140 encrypt lock](#the-fips-140-encrypt-lock).

## What a lane is

A lane is **not** a second tunnel. It is an extra session on the same
`HostInfo`.

Noise leaves both sides with `A.eKey == B.dKey` and `A.dKey == B.eKey`. Expanding
both keys through HKDF-SHA256 with the same per-lane label preserves that
equality, so both sides land on a matched key pair having exchanged nothing:

```
lane s send key = HKDF(base eKey, info: "nebula multiport lane v1 <s>")
lane s recv key = HKDF(base dKey, info: "nebula multiport lane v1 <s>")
```

(`connection_state.go:deriveLaneKey`. The base key is already unique per tunnel
and per direction, so the lane index is the only thing that needs to vary and no
salt is required.)

Consequences worth stating plainly:

- A lane costs **no handshake** and has no half-established state.
- A lane dies exactly when its base tunnel dies. There is no independent
  lifetime to reason about, no second teardown path.
- Each lane is a **full** session: its own message counter, its own replay
  window, its own cipher states, its own encrypt lock. Flows on different paths
  never contend for shared replay state, which is what makes reordering across
  lanes harmless, and under FIPS 140 the separate encrypt locks are what let one
  tunnel encrypt on more than one core.
- Rolling the base tunnel replaces every lane key, because lanes are derived
  from it. `maxMessageCounter` therefore reports the max across the base and all
  lane counters, so rehandshake and exhaustion thresholds see the real data
  volume rather than the base session's small share.

Which lane a packet belongs to travels in the nebula header, in the low 8 bits
of what used to be `Reserved` (see `header/header.go`). It is part of the AEAD's
associated data, so a lane index cannot be altered in flight -- a packet
decrypts on the lane it claims or not at all.

**Lane 0 is the base tunnel itself**: `HostInfo.ConnectionState`, the base port,
the peer's real remote address. It is not a special case reserved for control
traffic; it carries its share of data flows like any other lane.

## Socket layout

`routines` is **per port**. Each of `multiport.ports` consecutive ports gets its
own full group of `routines` sockets sharing it through `SO_REUSEPORT`, so total
sockets = total routines = total tun queues = `routines * multiport.ports`.

```
routines: 2, multiport.ports: 3, listen.port: 4242

              port 4242         port 4243         port 4244
             (lane 0/base)       (lane 1)          (lane 2)
            +-------------+   +-------------+   +-------------+
 writers[]  |  0  |  1    |   |  2  |  3    |   |  4  |  5    |
            +-------------+   +-------------+   +-------------+
 routine        0     1           0     1           0     1
```

Sockets are laid out **port-major**: `writers[s*routinesPerPort + r]` is the
r'th socket on port `listen.port+s`. So:

```go
laneSock(q, s) = s*routinesPerPort + q%routinesPerPort   // inside.go
egressSock(q)  = laneSock(q, 0)                          // base traffic
```

Two properties fall out of this, and the rest of the design depends on both:

1. **Every routine owns exactly one socket.** `listenIn` blocks in `recvmmsg`
   and everything downstream of it -- the batcher, the conntrack cache, the
   `txQueue` -- is single-owner and lock-free. More sockets than routines would
   need epoll or locks.
2. **Every routine has a sibling socket at the same group position on every
   port.** So socket selection is a pure function of `(queue, lane)` with no
   borrowing and no shared state, and each port's traffic spreads across its
   whole group rather than funnelling into one socket.

The second property is why `routines` is per port rather than a total to divide
up. With one socket per port, each port would be served by a single core -- worst
of all the base port, which carries every handshake, every lighthouse and punch
packet, every peer without multiport, and every tunnel whose lanes are down.

## Negotiation

Multiport capability rides the existing handshake payload as two new protobuf
fields (`handshake/payload.go`): `InitiatorLanes` field 9 and `ResponderLanes`
field 10, each a `LaneDetails{PortCount, BasePort, TxLanes}`.

- `PortCount` / `BasePort` -- the contiguous port range the sender bound, so the
  peer knows where to aim its lanes.
- `TxLanes` -- how many lanes the sender may send on, so the peer knows how many
  lane sessions it must be prepared to receive on.

Both are `nil` when multiport is off, which keeps the encoded payload
**byte-identical** to a vanilla one. A peer that has never heard of lanes skips
unknown fields as protobuf requires, and gets a plain tunnel.

From the result, `newLaneSet` computes:

```go
sessions  = min(max(myLanes, peerTxLanes), 256)  // we must be able to RECEIVE all of theirs
txLanes   = min(myLanes, peerPortCount, sessions) // we may only SEND on ports they bound
```

Sizing RX by the peer's count and TX by our own is what lets asymmetric hosts
work: a 4-port laptop talking to a 32-port server sends on 4 lanes and receives
on 32.

### Port pairing

Lane `s` targets `peerBasePort + ((s + portOffset) % peerPortCount)`.

`portOffset` is a per-pair FNV hash of the sorted vpn-address pair. Without it,
every small peer would aim its few lanes at a big peer's first few ports and
concentrate that peer's receive work on a couple of sockets.

The rotation has to cancel, though, or the two directions of one flow would take
unrelated 4-tuples and neither side's traffic would arrive through the conntrack
or NAT entry the other's probe opened. So both sides hash the *same* sorted pair
and the higher-addressed side **negates** the result. When the port counts match,
the two rotations cancel exactly: our lane `s`'s 4-tuple is the reverse of the
peer's lane `s`. `laneBias` does the matching rotation on the flow hash for the
same reason.

That pairing only exists when our lane indices map one-to-one onto the peer's
ports, which is exactly the `txLanes == peerPortCount` test `newLaneSet` applies
before setting `laneBias`. If we send on 4 lanes and the peer bound 8 ports, four
of its ports have no lane of ours pointing at them, and no choice of rotation can
make our lane `s` and its lane `s` be each other's reverse. So in that case
`laneBias` stays 0 and each side hashes the flow to a lane on its own. The flow
still works and is still spread; the two directions simply take two unrelated
4-tuples instead of one 4-tuple and its exact reverse, and each direction depends
on its own lane's probe having opened its own conntrack or NAT entry.

## Bringing a lane up

Receiving on a lane needs no permission: the keys are derivable the moment the
base handshake completes. **Sending** on one needs proof the new 4-tuple actually
works, because nothing else would notice a middlebox quietly dropping it. So:

```
lane down  --probe (Test/LaneProbe on lane s, from port base+s to peer's lane port)-->
           <--ack (Test/LaneProbeAck, on the BASE tunnel)--
lane up
```

- The probe is encrypted with **the lane's own session**, so an ack proves the
  whole lane end to end: our source port reached the peer, its reply reached us,
  and the keys we derived match the ones it derived.
- The ack rides the **base tunnel** on purpose. A probe proves the peer's lane
  works in *its* send direction; answering on our own lane `s` would make the
  result depend on a second path that can be broken independently.
- The ack echoes the header's lane, not the payload's, so a peer cannot get us to
  vouch for a lane it did not probe.
- A generation byte in the probe is echoed in the ack, so a late ack cannot
  promote a lane on the strength of a superseded probe.

`txAddr[s]` is a single `atomic.Pointer[netip.AddrPort]` that is *both* the TX
gate and the destination, so a data-plane routine that loads non-nil has
everything it needs in one atomic read and there is no window where one is set
and the other is not.

Probing is driven by the connection manager's per-tunnel traffic tick
(`maintainLanes` -> `probeLanes`), which only fires for a tunnel with traffic --
the same condition that makes a lane worth having. Timers:

| timer | value |
|---|---|
| probe timeout | 2s (shorter than the 5s tick on purpose) |
| keepalive | 30s |
| retry backoff | 5s, doubling to 60s |
| max failure count | 8 |

Traffic on a lane is not evidence the lane works -- that is the whole reason
lanes need probing -- so a lane that silently breaks is only caught by the
keepalive.

Every lane starts out **demanded**, so the first traffic tick probes all of them
at once. This matters more than it looks: see "flow pinning" below. A lane that
is down also raises demand from the TX path each time a flow wants it, so a
lane that keeps failing is retried only while something still wants it, and an
idle tunnel costs nothing.

A lane aims **only** at its own port. There is no fallback to the peer's base
port when the lane port doesn't answer: a lane sharing the base port's
destination would gain only a source port of its own while costing the peer the
receive spread that is the entire point. A lane that can't reach its port stays
down and its flows ride the base tunnel.

## Flow -> lane -> routine: keeping a flow consistent

This is the part that took the most iterations to get right, so it's worth
spelling out why it is shaped the way it is.

### The kernel's tun queue feedback loop

On Linux, a multiqueue tun device does not simply hash a flow to a queue. It
also *learns*: `tun_flow_update` records "this flow was last seen on queue *q*"
from the packets **we write in**, and `tun_automq_select_queue` prefers what it
learned over the hash for as long as the flow stays busy.

We write an inbound packet to the tun queue with the same index as the UDP
routine that received it (`batchers[rxc.q]`). So the queue a flow's *outbound*
packets arrive on is decided by the socket its *inbound* packets landed on, at
the far end, one RTT ago.

### Why the lane comes from the flow, not the routine

The obvious design -- routine `q` sends on lane `q` -- deadlocks against that
feedback loop:

1. A tunnel comes up. All lanes are down, so all traffic goes out lane 0.
2. The peer receives it all on socket 0 and writes it all to tun queue 0.
3. Both kernels now believe every flow belongs on queue 0.
4. Every flow is read by routine 0, so every flow picks lane 0.
5. Go to 2. The tunnel is pinned to lane 0 for as long as its flows stay busy.

So the lane comes from **the flow's own 5-tuple**, not from the routine index:

```go
s = (laneFlowHash(fwPacket) + laneBias) % txLanes    // lanes.go:txLaneForFlow
```

This makes lane spread completely independent of how the kernel steers tun
queues. It also gives the properties you actually want from a flow's point of
view:

- **A flow stays on one lane for its life.** The hash is a pure function of the
  5-tuple, so there is no per-packet lane hopping and therefore no reordering
  introduced by multiport.
- **One lane's replay window sees one stable set of flows.**
- **Both directions of a flow pick partner lanes.** `laneFlowHash` orders the two
  endpoints before hashing, so it returns the same value from either end, and
  `laneBias` lines the two sides' choices up. The two directions are exact
  reverse 4-tuples, which is what NAT and stateful firewalls need.

`newLaneSet` demanding every lane up front is the other half of this. Lanes have
to be up *before* the flows are: a flow that starts while the lanes are still
down gets its queue pinned by step 2 above and can stay there for its whole
life. Eager demand costs one probe per lane on any tunnel that has traffic, and
nothing at all on one that doesn't.

### The full path

```
  outbound                                     inbound (at the peer)
  --------                                     ---------------------
  inside flow
     |  kernel tun hash, or the queue it
     |  learned from our last write
     v
  tun queue q  ->  routine q
     |
     |  s = laneFlowHash(flow) % txLanes      lane s arrives on port base+s
     v                                           |
  lane s session                                 |  SO_REUSEPORT hash of the
     |                                           |  4-tuple picks one socket
     |  writers[laneSock(q,s)]                   v
     v                                       routine q' (owner of that socket)
  port base+s  ------------------------->        |
                                                 v
                                             tun queue q'  (teaches the kernel
                                                            flow -> q')
```

Note that RX is entirely socket-agnostic: the lane comes from the header byte,
not from the port the packet arrived on, and roaming is skipped for `lane != 0`
(a lane's source address is a per-lane 4-tuple, not the tunnel's remote -- letting
it roam the hostinfo would point every non-lane packet at a lane port). So a
lane packet may legitimately arrive on any socket, which is what makes the
reuseport spread within a port safe.

### Ordering and locking

Several routines can write to one socket, since the routines whose lane
arithmetic lands on the same index share it. Linux's `batchWriter` serializes
`sendmmsg` with a mutex. Per-flow wire order still holds regardless: a flow is
hashed onto one lane and read by one routine, so nothing else is writing that
flow.

Each routine holds one `txQueue` with one shared arena (~1.16 MB) and builds a
`SendBatch` per lane lazily, on the first packet that picks it, so a routine that
never sends on a lane never pays for one.

### The FIPS 140 encrypt lock

In FIPS 140 mode -- a `boringcrypto` build, or `GODEBUG=fips140=on` -- nebula
uses `noiseutil.CipherAESGCMFIPS140` instead of the plain AES-GCM cipher. That
cipher is the TLS 1.3 GCM (`GCMWithXORCounterNonce`), which **panics** if it is
asked to seal with a counter that is not strictly greater than the last one. That
check is the point: it is the nonce-reuse protection FIPS 140 requires, and
`noiseutil`'s startup self-test refuses to run if the check has gone missing.

The check means encrypts on one session cannot overlap, so
`noiseutil.EncryptLockNeeded` is true and every send path takes that session's
`ConnectionState.writeLock`:

```go
if noiseutil.EncryptLockNeeded {
        ci.writeLock.Lock()
}
c := ci.messageCounter.Add(1)
out = header.EncodeLane(scratch, ..., c, lane)
out, encErr := ci.eKey.EncryptDanger(out, out, seg, c, nb)
if noiseutil.EncryptLockNeeded {
        ci.writeLock.Unlock()
}
```

The lock has to cover the seal and not just the counter increment. Reserving
counters atomically is easy; the requirement is that the seals *arrive at the
AEAD in counter order*, and only holding the lock across both gives that.

So under FIPS 140 the encrypt cost of a tunnel is pinned to one core. `routines:
N` gives N readers, but every one of them that has a packet for the same peer
queues on the same mutex, and with TSO/USO the lock is taken and released once
per segment -- up to ~45 times for a single superpacket
(`sendInsideEncrypt`). Receive is not affected: `extractFIPSAEAD` deliberately
pulls the inner FIPS AEAD out of the `crypto/tls` wrapper because that inner
implementation is safe to `Open` concurrently, and `decryptLock` is only ever
held around the replay-window check and update.

Lanes split the lock because a lane is a separate `ConnectionState`: its own
`writeLock`, its own message counter, its own nonce sequence. A peer we send to
on `txLanes` lanes has `txLanes` independent encrypt locks, so encrypt for that
one tunnel can run on that many cores at once.

The flow hash is what makes this work rather than merely legal. A flow maps to
one lane, so all of a flow's packets take one lock in counter order -- exactly
what the FIPS AEAD demands -- while different flows to the same peer land on
different locks. Contention is divided, not eliminated: any routine may send on
any lane, so two routines whose flows hash to the same lane still serialize
against each other.

Two caveats. This is only a FIPS 140 benefit -- in a normal build
`EncryptLockNeeded` is false, encrypt is lock-free, and lanes buy path and queue
spread only. And it is not unilateral: `txLanes` is bounded by the peer's port
count, so a peer that binds one port leaves us back on one encrypt lock however
many ports we bound ourselves.

## Falling back to the old behavior

Multiport degrades rather than failing, at every level. This is deliberate:
managed deployments can't be hard-errored on config they don't control.

### Whole-node: back to one port

Any of these turns multiport off, logs why, and leaves a node that binds one
port with `routines` `SO_REUSEPORT` sockets -- bit-for-bit the pre-multiport
configuration:

| condition | log |
|---|---|
| `multiport.enabled: false` | - |
| `multiport.ports` unset, 0, or 1 | `multiport disabled: set multiport.ports > 1 ...` |
| `listen.port + ports - 1 > 65535` | `multiport disabled: would bind ports beyond 65535` |
| platform can't run multiple UDP readers | `multiport disabled: this platform does not support multiple udp readers` |
| that capability couldn't be probed | `multiport disabled: could not probe udp reader support` |

`multiport.ports` is also clamped to 256 (the lane header limit) and to
`maxRoutines / routines`, with a warning, rather than being rejected.

With a dynamic `listen.port: 0`, the first socket binds dynamically and the
range is claimed above it; a partially-occupied range re-rolls with a fresh
dynamic port up to 6 times.

`laneSock` collapses to the identity when multiport is off, so the send path is
unchanged: a routine writes to its own socket and no lane batches are built at
all.

### Per-tunnel: back to a single session

`newLaneSet` returns `nil`, and the tunnel is an ordinary one, when:

- the peer advertised no port count (vanilla peer, or multiport off there), or
- `sessions < 2`, i.e. neither side offers a lane.

`txLanes` can also land at 1 -- we bound ports but the peer bound only one -- in
which case the set exists for RX but we never send on a lane.

### Per-packet: back to the base tunnel

`txLaneForFlow` returns a nil session and the packet rides the base tunnel,
decided per packet with no state to unwind:

- the flow hashed onto lane 0 (its fair share of flows);
- the lane it hashed onto has never come up;
- the lane was **demoted** -- a probe or keepalive went unanswered. Fallback is
  immediate, on the very next packet, and the miss re-raises demand so the lane
  is re-probed;
- the tunnel is **relayed** -- lanes are direct-only, so `probeLanes` drops them
  all when there is no direct path and rebuilds when one returns;
- the peer **roamed** -- a new NAT mapping has no derivable relationship to the
  old lane ports, so every lane is torn down and re-probed from a clean backoff.
  Standing demand is deliberately kept across a reset, so the lanes that were
  actually carrying data come back first.

### Always on the base tunnel

Handshakes, lighthouse traffic, punching, relay carriers, close packets, rejects,
and lane probe *acks* all use the base session and a socket on the base port
(`egressSock`). Base traffic must keep the base source port or a vanilla peer
would see the tunnel's address move and roam-thrash.

`recv_error` is the one deliberate exception: it replies from the socket the
offending packet arrived on, because a lane peer's spoof guard compares our
source address against that lane's remote and would discard a reply from the
base port.

### Wire compatibility

- A vanilla sender emits lane 0 in a field it thinks is reserved, and lane 0 is
  the base tunnel, so it reads correctly with no version check.
- We always send the upper 8 reserved bits as zero.
- A lane index above what this tunnel has (a stale lane from a rolled tunnel, or
  a peer sending above what it advertised) is dropped **silently** -- a
  `recv_error` would tear down a perfectly good base tunnel on the strength of
  one odd packet.
- Lane ciphertext wrapped in a relay carrier is refused before the session
  lookup, so a junk relay packet can't make us derive a session.

## Security notes

- The lane index is in the AEAD's associated data, so it is authenticated, not
  just carried.
- On RX, a lane session derived for an unrecognized lane is **not installed**
  until the packet actually decrypts. Anyone who can spoof this tunnel's local
  index can name any lane; installing on sight would let them make us hold a
  replay window and two cipher states per lane, per tunnel, for lanes they never
  send on.
- Two routines racing on a lane's first packet each derive a session. The loser's
  is dropped, and its replay-window entry for the packet it just accepted is
  handed to the winner (`installSession`) -- the keys are identical, so it is the
  same window in every respect that matters.

## Configuration

```yaml
routines: 8          # PER PORT under multiport; total workers = routines * ports
multiport:
  enabled: true      # default true, but inert without ports
  ports: 4           # consecutive ports from listen.port; must be > 1, no default
  lanes: 0           # 0 = one per bound port; lower to send on a subset
```

`multiport.ports` has no default on purpose: under these semantics a default
would silently multiply the worker count. Nothing here is reloadable.

Both sides need a port range, and the range
`[listen.port, listen.port+ports-1]` must be open in both directions. Opening
only the base port is the common failure and gives you exactly one working lane
-- the one whose rotation happens to land on the base port.

## Observability

```
nebula-ssh> print-tunnel -vpn-addr <peer>
```

`lanes[]` gives per-lane `up`, `remote` and `messageCounter`, which is the fastest
way to tell "no lanes negotiated" (key absent) from "lanes up but traffic on one"
(counters).

Metrics, registered only when multiport is running so they don't sit at zero on
nodes without it:

- `multiport.lanes.up` -- lanes currently carrying traffic
- `multiport.lanes.tunnels` -- tunnels with any lanes

Both are counted by walking the hostmap rather than kept at promotion/demotion,
because a counter would drift upward forever: a tunnel torn down with its lanes
up never demotes them.

Logs worth grepping: `multiport enabled` and `multiport routines` at startup, the
`lanes` attr on handshake completion (`tx`, `sessions`, `peerBasePort`,
`peerPorts`, `portOffset`), and `Multiport lane up` / `Multiport lane demoted`,
both of which name the `udpAddr` involved.

## Known gaps

- No `readOutsidePackets`-level test for the RX lane drop paths.
- No multiport coverage in the e2e suite.
- `routines * ports > 256` fails at startup from the kernel's tun queue limit
  rather than being clamped with a warning.
