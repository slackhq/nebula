# Post-quantum handshakes

Status: draft. Decisions below were made on 2026-10-13; open items are listed at the end.
Phase 1 is implemented (see [Implementation](#implementation-phase-1)).

## Goals

1. **Confidentiality against harvest-now-decrypt-later.** Traffic recorded today must stay
   secret after a cryptographically relevant quantum computer exists. This needs a
   post-quantum key exchange now.
2. **Post-quantum authentication, later.** Needs certificates whose CA signature and host
   keys are post-quantum. This requires reissuing certificates, so it ships second.
3. **Never rely on IP fragmentation.** ML-KEM and ML-DSA do not fit in one packet, so the
   handshake must carry messages larger than the path MTU itself.

Non-goals: identity hiding beyond what IX offers today, and signatures at handshake time.
The only signature in the system stays the CA signature inside the certificate.

## Primitives and sizes

| Primitive | Size |
|---|---|
| ML-KEM-1024 encapsulation key | 1568 B |
| ML-KEM-1024 ciphertext | 1568 B |
| ML-DSA-87 public key / signature | 2592 B / 4627 B |
| Today's IX msg1 / msg2 (v2 cert, 151 B) | 252 B / 287 B |

`crypto/mlkem` is available in Go 1.26 (the current `go.mod`); `crypto/mldsa` arrives in
Go 1.27 and is only needed for phase 2.

## Phase 1: ephemeral ML-KEM on today's certificates

A new handshake subtype, `ix_psk2_mlkem1024` (2), IX-shaped (2 messages; the responder
completes on msg1 as today), using the flynn/noise `psk2` modifier. The Noise protocol name
becomes `Noise_IXpsk2_...`, which separates it from the classical subtype.

- **msg1**: the initiator generates a fresh ML-KEM-1024 key pair and places the
  encapsulation key in `NebulaHandshakeDetails.KEMKey` (field 9). msg1's payload is mixed
  into the Noise transcript, so it cannot be stripped or replaced without msg2 failing.
  With the psk modifier Noise also mixes `e` into the cipher key, so msg1's static key and
  payload are encrypted, though only under a key derived from the public ephemeral.
- **Responder**: after `ReadMessage(msg1)` it encapsulates to that key, obtaining
  `(ct, ss)`, and calls `HandshakeState.SetPresharedKey(psk)` before writing msg2, with
  `psk = HKDF-Extract(SHA-256, salt = "nebula ix_psk2_mlkem1024 v1", ikm = ss || ct)`.
  The ciphertext is bound in because, unlike the encapsulation key, it is not part of the
  Noise transcript.
- **msg2** on the wire is `ct || noise_msg2`. The ciphertext travels outside the Noise
  message because the initiator needs `ss` before processing msg2's `psk` token. Any change
  to `ct` yields a different `ss` (ML-KEM implicit rejection) and the handshake fails.

Transport keys depend on both the X25519 DH outputs and the ML-KEM shared secret.
Authentication is unchanged and classical. With a minimal v2 certificate msg1 and msg2 are
about 1.84 KB each, so each travels as 2 data and 2 repair fragments of about 936 bytes.
A KEM key on the classical subtype, or a missing or malformed one on this subtype, is a fatal
protocol error; a forged ciphertext only fails that packet.

## Phase 2: pqIX hybrid with certificate v3

Certificate v3 is hybrid: the classical static key and CA signature plus a static
ML-KEM-1024 key and an ML-DSA-87 CA signature. Host authentication is by KEM rather than by
signature, following PQNoise's pqIX, while keeping the classical DH tokens:

- **msg1** (I to R): `e, s`, ephemeral ML-KEM key, initiator cert.
- **msg2** (R to I): `e, s`, ciphertext to I's ephemeral KEM key, ciphertext to I's static
  KEM key, responder cert.
- **msg3** (I to R): ciphertext to R's static KEM key, plus first data. R authenticates I
  when msg3 decrypts; I authenticates R implicitly when R's first reply decrypts.

msg3 is about 1.6 KB, 2 data and 2 repair fragments, and adds no new message types:

- **Responder.** After sending msg2 the responder keeps a pending Machine, found by its
  local index like the initiator's today; this is the multi-message responder support the
  manager lacks now. A repeat msg1 maps to it through the answered-msg1 cache and gets msg2
  resent with fresh symbols, exactly as in phase 1. Until msg3 verifies, data for that
  index is dropped silently: it must not draw a RecvError, which would tear down the
  initiator's new tunnel. On completing it sends an empty `Test`/`TestReply` under the
  new keys, so the initiator hears back even when there is no traffic.
- **Initiator.** Writing msg3 yields the transport keys, so the hostinfo moves to the main
  hostmap and data flows at once, readable only by the real responder. The handshake entry
  stays behind in a confirming state: each retry tick resends msg3 with fresh symbols until
  any packet from the responder decrypts on the new tunnel, and if that never happens
  within the handshake timeout the tunnel is torn down. Losing msg3 costs the data sent
  behind it, which the overlay's own transport retransmits.
- msg3's fragments use the responder's index as RemoteIndex and land on the responder's
  pending entry, so they never enter the pre-authentication table.

The initiator never caches the responder's certificate, so every handshake has three
messages and carries both full certificates. With ML-DSA-87:

| Message | Size | Data fragments (k) |
|---|---|---|
| msg1 | ~8.2 KB | 8 |
| msg2 | ~9.8 KB | 9 |
| msg3 | ~1.6 KB | 2 |

flynn/noise cannot mix multiple KEM secrets into the chaining key, so phase 2 needs a
KEM-aware Noise symmetric state written in this repository. Both subtypes coexist.

Cryptographic review of the hybrid composition will be done by in-house cryptographers.

## Fragment transport

### Requirements

- No IP fragmentation: every datagram's UDP payload is at most 1232 bytes **after** relay
  wrapping (16 B header + 16 B tag), the IPv6 minimum MTU budget also used by DNS Flag Day
  2020 and Solana's Turbine.
- Every fragment of a handshake uses the same 5-tuple.
- Bounded pre-authentication state, bounded amplification, selective loss recovery,
  tolerance of reordering and duplication, and a strictly validated, fuzzable parser.

### Wire format

Every packet of a fragmented handshake subtype is:

```
Nebula header (16)   Version | Type=Handshake | Subtype | Reserved=0 | RemoteIndex | Counter
Fragment header (8)  FragID u32 | MsgLen u16 | Index u8 | Flags u8
Cookie (16)          only when Flags has 0x01
Symbol               SymbolSize bytes
```

- `Counter` is the Noise message number (1, 2, 3). `RemoteIndex` is 0 for msg1, as today.
- `FragID` is the sender's local index (random, non-zero).
- `MsgLen` is the length of the whole message. Both ends derive the layout from it:
  `K = ceil(MsgLen / 1160)`, `SymbolSize = ceil(MsgLen / K)`. Every symbol has the same
  size. Room for a cookie is always reserved, so a packet is at most
  16 + 8 + 16 + 1160 = 1200 bytes with or without one.
- `Index < K` is a data symbol (a slice of the message, the last one zero padded);
  `Index >= K` is a repair symbol.
- `Flags` bit 0x01 means a cookie follows the fragment header. Other bits must be zero.

A cookie reply, sent by a responder under load, is a bare 32 byte packet:

```
Nebula header (16)   Version | Type=Handshake | Subtype | Reserved=0 | RemoteIndex=FragID | Counter=0
Cookie (16)
```

It names the initiator's FragID, so the initiator finds its attempt the same way it finds
msg2.

### Forward error correction

Messages are protected with a systematic Reed-Solomon code over GF(2^8), implemented in
`handshake/fec`:

- The repair rows form a Cauchy matrix, `coefficient(row, col) = 1 / (row XOR col)` with
  `row >= K > col`, so every square submatrix is invertible and **any K distinct symbols
  reconstruct the message**. Naive identity-over-Vandermonde constructions are not MDS
  (the PAR1 flaw and the 1997 Plank tutorial erratum).
- A repair row depends only on its index, so repair symbols are generated on demand and
  their indexes never need to be agreed in advance. Up to 256 symbols exist per message.
- Known-answer vectors in `fec_test.go` pin the encoding and were cross-checked against an
  independent implementation; changing them is a wire format change.
- Cost for a 9.8 KB message (k=9): about 13 µs for three repair symbols, about 19 µs to
  decode with three data symbols missing.

**The sender chooses m**, the number of repair symbols per attempt. The receiver only needs
any K symbols, so this is policy and can change without a protocol change. The starting
rule is `m = max(2, ceil(K/3))`.

**Retries send fresh symbols.** Attempt 0 sends indexes `0 .. K+m-1`; each retry sends
the next `K+m` unused indexes. The receiver merges all distinct symbols across attempts,
so no received fragment is wasted. Indexes are a deterministic function of the message,
so retransmits stay idempotent: the responder caches msg2 itself and regenerates any
symbol.

**Repair symbols trail the data.** Data symbols go out back to back; repair symbols follow
after a short delay, so a queue tail-drop at the end of the data run does not also take the
repair. In simulation this lifts small messages substantially (k=2 at 10% loss, burst 8:
91.4% to 98.2% first-attempt success). Pacing every fragment was also evaluated; it gains
about 5 more points for k=7..9 on bursty paths, which is not worth the extra machinery,
and the retry with fresh symbols covers the remainder.

### Receiver rules

Implemented in `handshake/fragment` (`Sender`, `Assembly`, and the capped `Table`).

- Fragments are stored individually as they arrive and charged against a memory cap.
  Nothing is allocated from a claimed size alone (FragmentSmack, game-engine "fragment
  bombs").
- `MsgLen` must be identical for every fragment of a `FragID`; a mismatch drops the whole
  entry. msg1 is capped at `MsgLen <= 16384` (K <= 15).
- The decoder keeps at most K distinct symbols, so an entry never exceeds about MsgLen bytes
  however many repair symbols arrive.
- When K symbols are present the message is decoded and handed to the handshake `Machine`
  as a synthetic `[header | message]`. The Machine never sees fragments.
- A completed entry is forgotten immediately. A late duplicate fragment starts a new entry
  and, once enough arrive, reconstructs the same message again; the handshake layer's
  duplicate detection recognises it.
- If Noise rejects a decoded message, the entry is discarded and the next attempt
  supplies fresh symbols. (Possible refinement: keep a few spare symbols so an injected
  bad symbol can be identified by re-encoding instead of waiting for a retry.)
- Pre-authentication msg1 entries live in a table keyed by (source address or relay index,
  FragID) with a total memory cap, per-source quotas (/32 for IPv4, /64 for IPv6), a
  sliding TTL of about 2 s refreshed by progress, and random eviction under pressure.
  msg2 and msg3 reassembly attaches to the existing pending handshake found by RemoteIndex.

### Retransmission and amplification

- Only timers cause transmission. Reactive resends (the responder resending its cached
  msg2 when a duplicate msg1 completes) are rate limited to one per handshake per retry
  interval, to avoid TFTP's Sorcerer's Apprentice amplification.
- Duplicate msg1 detection compares the decoded message to the cached one **before**
  running Noise or certificate verification.
- Before an address is validated, a responder sends at most 3x the bytes it received from
  it (QUIC's rule). Normal handshakes sit near 1.1-1.2x.
- In phase 2 the initiator retransmits msg3 until any authenticated packet arrives from
  the responder; the responder sends a small confirmation on completion and holds tunnel
  traffic until msg3 verifies.

### Denial of service

The responder can no longer complete statelessly on msg1, since msg1 arrives in pieces.
Defenses are the capped table above plus a **cookie under load**, in the style of
WireGuard's mac2, QUIC Retry and the SCTP state cookie:

- Once the msg1 table is at least half full (by bytes or by entries), every msg1 fragment
  must carry a valid cookie. One without is answered with a cookie reply and leaves no
  state. Fragments that already belong to an entry need one too, so an attacker cannot
  hold old entries open.
- A cookie is `HMAC-SHA256(secret, source address and port, relay channel, FragID)`
  truncated to 16 bytes. The secret rotates every 2 minutes and the previous one is still
  accepted, so a cookie is good for 2 to 4 minutes.
- Replies are never larger than the packet that prompted them (no amplification) and are
  rate limited as a whole (a burst of 256, then 1000 per second), so spoofed floods cannot
  turn the responder into a reflector.
- The initiator attaches the cookie to its PQ attempt, so every later packet carries it,
  and immediately resends fresh symbols to the address the reply came from, at most once
  per retry interval. Under load a PQ handshake costs one extra round trip, which in
  practice still beats the classical attempt on the next retry tick.
- An attacker on the path can forge a cookie reply; the bogus cookie is simply rejected
  and answered with a real one.

A CA-keyed pre-filter MAC was considered and rejected: networks commonly trust many CAs.

#### Injected symbols

The decoder keeps the first K distinct symbols it sees, so one forged symbol in those K
spoils that attempt's decode; Noise rejects the result and the next attempt brings fresh
symbols. Forging one needs the attempt's FragID or index, which are random 32 bit values,
and for msg1 the initiator's exact address and port too, so in practice only an attacker
who sees the traffic can do it. An attacker who can also drop packets gains nothing new.
One who can only inject, and races a forged symbol into every attempt, can stop a PQ
handshake where it could not stop a classical one, since classical msg2s are tried one
packet at a time. Keeping spare symbols to find a consistent subset only raises the number
of forgeries needed per attempt, and authenticating symbols is impossible for msg1, which
travels before any key exists. So the decoder deliberately does neither. A non-sticky
initiator still gets a classical tunnel from its next attempt; a sticky one, by design,
does not downgrade.

## Rollout

- Separate settings for initiating and accepting PQ handshakes, both off by default:
  `handshakes.pq.initiate`, `handshakes.pq.accept`. `handshakes.pq.repair_delay` (default
  10ms) sets how long repair fragments trail the data fragments.
- `handshakes.pq.require` makes every handshake PQ: it implies `initiate` and `accept`,
  never offers a classical attempt, and drops classical msg1s.
- Old nodes silently drop unknown subtypes, so discovery is speculative: an initiator with
  `initiate` enabled alternates PQ and classical attempts on successive timer retries,
  keeping both pending, and the first to complete wins. A path nothing has been sent over
  yet gets the PQ attempt first: an early resend triggered by a lighthouse reply is PQ, and
  a relay that comes up pushes the PQ attempt through at once, counting as the PQ turn.
  Without that, relays set up during the first attempt handed every relayed handshake to
  the classical retry (seen on real hosts: 11 of 11). Once a msg2 fragment or cookie reply
  arrives for the PQ attempt the peer evidently speaks PQ, and classical stops getting
  turns.
- All `handshakes.pq` settings reload without a restart. Handshakes in flight carry on;
  the new settings apply to the next attempt and the next packet.
- `handshakes.pq.sticky` (default off): once a peer has completed a PQ handshake, never fall
  back to classical for it again during this process lifetime. This resists active
  downgrade after first contact.
- No lighthouse capability advertisement.

## Simulation results

Gilbert-Elliott channel (bad state drops everything), losses expressed as average rate and
mean burst length in packets. First-attempt success for the whole handshake with
`m = max(2, ceil(K/3))` and repair delayed 16 packet slots, compared with no FEC:

| Handshake | Loss | Burst 1 | Burst 2 | Burst 4 | Burst 8 |
|---|---|---|---|---|---|
| phase 1 (2, 2) no FEC | 5% | 81.4% | 85.6% | 87.9% | 89.0% |
| phase 1 (2, 2) FEC | 5% | 99.9% | 99.4% | 99.3% | 98.6% |
| phase 1 (2, 2) FEC | 10% | 99.3% | 97.5% | 97.4% | 96.3% |
| phase 2 (7, 9, 2) no FEC | 5% | 39.8% | 57.5% | 70.4% | 77.7% |
| phase 2 (7, 9, 2) FEC | 5% | 99.6% | 94.2% | 90.4% | 88.8% |
| phase 2 (7, 9, 2) FEC | 10% | 95.9% | 84.6% | 79.0% | 77.3% |

With fresh repair symbols, phase 2 completes within two attempts at least 99.1% of the time
in every scenario above, and within three at least 99.99%.

## Prior art

- **WireGuard / Rosenpass**: fit every message in one packet; cookies and biscuits for
  statelessness. Not possible at our sizes.
- **IKEv2**: RFC 7383 fragments only after keys exist, with each fragment authenticated;
  RFC 9242/9370 move PQ key exchange into intermediate exchanges for that reason.
- **QUIC / DTLS 1.3**: offset-based reassembly with ACKs; QUIC's 3x amplification limit and
  1200-byte floor.
- **Solana Turbine**: Reed-Solomon over 1232-byte UDP packets through untrusted relays;
  moved to Merkle-authenticated shreds after unauthenticated repair symbols enabled
  poisoning.
- **kcp-go, UDPspeeder, CM256**: RS FEC over UDP; parity must scale up for small groups.
- **gQUIC FEC (removed)**: FEC does not pay for bulk transfer under bursty loss; it does
  for short, latency-critical transfers such as handshakes.
- **TFTP, NFS duplicate request cache, memcached UDP, IP reassembly bugs**: retransmit
  storms, ID-wrap misassembly, reflection amplification, and allocation from claimed sizes.

## Implementation (phase 1)

- `handshake`: the `ix_psk2_mlkem1024` subtype (`patterns.go`, `kem.go`), the `KEMKey`
  payload field, and the psk2 plumbing in `Machine`.
- `handshake/fec`, `handshake/fragment`: the code and the fragment transport.
- `handshake_manager_pq.go` and the manager:
  - **Initiator.** Attempts alternate PQ and classical, starting with PQ (sticky peers get
    only PQ). The PQ attempt has its own local index registered alongside the classical
    one; whichever response completes first wins, and the other index is released
    (`settleIndex`). A timed out or deleted pending handshake releases both.
  - **Responder.** msg1 fragments go into the capped pre-authentication table. A decoded
    msg1 is looked up by hash among recently answered ones before any Noise, KEM or
    certificate work: the trailing repair fragments of an attempt rebuild a msg1 its data
    fragments already completed, and a retrying initiator offers fresh symbols for the
    same msg1. A repeat goes straight to the cached-response resend, which offers fresh
    msg2 symbols, is rate limited to one per retry interval and is held to the 3x
    amplification budget.
  - **Relays** carry fragments unchanged; repair fragments trail via a timer.
- The pre-authentication table is capped at 4 MiB, 1024 entries, 4 per source (IPv4 /32,
  IPv6 /64, or relay channel), 16 KiB messages and a 3 s idle timeout. Cookies are
  demanded from half full.
- Tests: Noise-level KEM tests, codec and fragment tests and fuzzers, manager unit tests
  for the response budget and rate limit, and e2e tests for a clean handshake, loss of
  data fragments in both directions, fallback to a peer that does not accept PQ, a lost
  msg2 recovered by fresh symbols, sticky mode under an attacker dropping PQ packets,
  relays, index cleanup on completion, fallback and timeout, and a responder flooded from
  spoofed sources demanding and accepting a cookie. Unit tests cover cookie binding and
  rotation, the never-amplify rule, the initiator's rate limited resend, and reload. ML-KEM and HKDF also
  pass under `GOEXPERIMENT=boringcrypto` and `GODEBUG=fips140=on`.

## Open items

None for phase 1. Phase 2 needs certificate v3, the KEM-aware Noise symmetric state, and
the msg3 design above.
