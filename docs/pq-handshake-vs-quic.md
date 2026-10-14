# Post-quantum handshake transport compared with QUIC

Status: analysis, 2026-10-14. Compares the fragment transport in
[pq-handshake.md](pq-handshake.md) with how QUIC makes its handshake reliable. TLS is out of
scope; only the transport mechanics are compared.

## Summary

QUIC's handshake reliability is closed-loop: the receiver acknowledges, and the sender
repairs exactly what is missing. Ours is open-loop: repair symbols are sent up front, and a
timer sends fresh symbols. At handshake sizes (K <= 15) a QUIC-style acknowledgement
shrinks to a 16-bit bitmap, and with an MDS code to a single count. So the real comparison
is forward error correction versus acknowledgements, not QUIC versus us.

FEC is the right core. One piece of feedback is worth adding, initiator to responder and for
msg2 only (see [Worth taking from QUIC](#worth-taking-from-quic)).

## What QUIC does

- **Messages as a stream.** Handshake bytes travel as `CRYPTO` frames (offset and length)
  and are reassembled in order. Initial and Handshake packets each have their own packet
  number space.
- **Immediate acknowledgements.** Receivers must acknowledge Initial and Handshake packets
  without delay. ACK frames list ranges of received packet numbers.
- **Loss detection** (RFC 9002). A packet is lost once 3 later packets are acknowledged, or
  after 9/8 of the round-trip time. Lost bytes are resent in new packets.
- **Probe timeout (PTO).** If a whole flight vanishes, a probe timer fires. Before any RTT
  sample it starts at about 1 s (333 ms initial RTT plus 4x its variance) and doubles each
  time. Both endpoints run it.
- **Amplification limit and anti-deadlock.** The server may send at most 3x what it
  received until the client's address is validated. The client must keep probing so a
  server stuck at that limit cannot deadlock.
- **Retry.** A stateless round trip to validate the address. `NEW_TOKEN` lets later
  connections skip it.
- **Congestion control from the first packet.** The initial window is 10 packets of 1200
  bytes.

## Side by side

| | QUIC | pq-handshake |
|---|---|---|
| Receiver feedback | ACK ranges, sent immediately | None; the next handshake message is the only acknowledgement |
| Partial loss | +1 to 2 RTT (ACK, detect, resend) | 0 RTT while at most m symbols are lost |
| Total loss | PTO: about 1 s, then doubling | Next PQ tick: 300 ms, then 1 s (alternating), or 100/300/600 ms (sticky) |
| Spurious retransmit | Wasted bytes | Still useful: fresh repair indexes add to what the receiver holds |
| Reassembly | Every byte offset, in order | Any K of up to 256 symbols |
| Who retransmits | Both sides on their own timers | Initiator on a timer; the responder resends msg2 only when a repeat msg1 arrives (rate limited) |
| State from the first packet | Server buffers and acknowledges partial flights | Capped pre-authentication table that never acknowledges |
| Address validation | Retry, 1 RTT | Cookie under load, 1 RTT |

From the [simulation results](pq-handshake.md#simulation-results): phase 2 at 5% random
loss with no FEC completes on the first attempt 39.8% of the time. Under
acknowledgement-based recovery roughly 60% of handshakes would pay at least one extra round
trip. With FEC, 0.4% wait for a retry. Spending bandwidth to save round trips is the stated
design preference, and open-loop recovery delivers it.

## Where the designs already agree

- **1200-byte floor and the 3x amplification budget**, both taken directly from QUIC.
- **Cookie and Retry.** Both cost one round trip and both can be forged by an on-path
  attacker. QUIC's Retry integrity tag uses a fixed, published key.
- **On-path injection.** QUIC's Initial keys are derived from the client's connection ID,
  which an observer can read, so QUIC accepts the same handshake-blocking injection
  weakness documented for our symbols in
  [Injected symbols](pq-handshake.md#injected-symbols).
- **Phase 2 msg3 confirmation.** Resending msg3 until any authenticated packet arrives,
  with a `Test` from the responder on completion, is QUIC's handshake confirmation and
  `HANDSHAKE_DONE`.

## Worth taking from QUIC

### 1. A msg2 progress probe from the initiator

This is the main gap. Today, recovering a partially lost msg2 means the initiator resends a
full msg1 attempt; the responder decodes it, matches it in the answered-msg1 cache, and
resends msg2. In phase 2 that is about 12 fragments (~13 KB) uploaded just to act as an
acknowledgement, and recovery waits for the 300 ms or 1 s tick.

- The initiator already knows the responder's index: msg2 fragments carry it as `FragID`
  (`sendFragmentedResponse` passes `hostinfo.localIndexId`).
- A one-packet probe, "msg2: have n of K", sent to that index would recover in about one
  round trip. The responder finds it the way phase 2 plans to find msg3.
- Timing comes for free: msg1 send to first msg2 fragment is an RTT sample. Probe at
  roughly RTT/8 plus the repair delay after the first msg2 fragment if decoding has not
  completed.
- Forging a probe needs the 32-bit responder index, so only an on-path attacker can, and
  the existing 3x budget bounds the reply.
- If no msg2 fragment arrived at all, the initiator keeps today's msg1 resend. That is the
  same tail-loss case QUIC's PTO covers.

The reverse direction, the responder reporting progress on msg1, should not be added. It
needs per-entry timers on the pre-authentication path, which is exactly the state QUIC
servers carry and the reason QUIC needs Retry.

### 2. Buffer early data in phase 2

QUIC stacks hold a few packets they cannot decrypt yet. The phase 2 plan drops data that
reaches the responder before msg3 decodes. Because repair fragments trail by
`handshakes.pq.repair_delay` (10 ms), losing one msg3 data fragment drops about 10 ms of
the initiator's first data while the repair is in flight. A small queue on the pending
responder entry, replayed once msg3 verifies, avoids this.

### 3. Burst size across remotes

QUIC handshakes on a single path. `handleOutbound` sends the same `now` and `later` sets to
every known remote and to relays (`StartRelays`).

- Phase 1 is fine.
- In phase 2, four remotes means about 48 packets (~54 KB) leaving one uplink at once,
  every PQ tick, about 4x QUIC's initial window.
- The Gilbert-Elliott simulation treats each path independently, so it does not capture
  this self-inflicted burst on a constrained uplink such as cellular.
- Options: send the full FEC set only to the most likely remote and a reduced set to the
  others, or interleave packets across remotes.

## Not worth taking

- **Packet numbers, ACK ranges, an RTT estimator, loss thresholds, congestion control.**
  QUIC pays for this machinery because it also serves a data transport. Nebula carries
  packets and leaves reliability to the overlay's own transports. Building it only for
  handshakes of at most 15 fragments buys nothing a symbol count cannot.
- **Offset-based reassembly.** It gives up the any-K-of-256 property and makes spurious
  retransmits wasteful again.
- **An RTT-adaptive retry timer.** Low value. The fixed 100 ms linear schedule already fires
  sooner than QUIC's 1 s first PTO, and a spurious resend costs bandwidth, not correctness.

## Conclusion

Keep FEC as the core and add the msg2 progress probe. That gets QUIC's roughly one round
trip tail recovery without pre-authentication state, and cuts phase 2's retry cost on the
uplink by about 10x. Items 2 and 3 are phase 2 concerns; item 1 also helps phase 1.
