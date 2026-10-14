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

The initiator never caches the responder's certificate, so every handshake has three
messages and carries both full certificates. With ML-DSA-87:

| Message | Size | Data fragments (k) |
|---|---|---|
| msg1 | ~8.2 KB | 7 |
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
Symbol               SymbolSize bytes
```

- `Counter` is the Noise message number (1, 2, 3). `RemoteIndex` is 0 for msg1, as today.
- `FragID` is the sender's local index (random, non-zero).
- `MsgLen` is the length of the whole message. Both ends derive the layout from it:
  `K = ceil(MsgLen / 1176)`, `SymbolSize = ceil(MsgLen / K)`. Every symbol has the same
  size, so a packet is at most 16 + 8 + 1176 = 1200 bytes.
- `Index < K` is a data symbol (a slice of the message, the last one zero padded);
  `Index >= K` is a repair symbol.
- `Flags` is reserved for a cookie extension and must be zero.

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
  entry. msg1 is capped at `MsgLen <= 16384` (K <= 14).
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
Defenses are the capped table above plus a **cookie under load**: when the table is under
pressure, a fragment from an unvalidated address is answered with a stateless cookie
(a MAC over source address, FragID and a time bucket), and the initiator resends with the
cookie. This costs a round trip only while under attack, in the style of WireGuard's
mac2, QUIC Retry and the SCTP state cookie. A CA-keyed pre-filter MAC was considered and
rejected: networks commonly trust many CAs.

## Rollout

- Separate settings for initiating and accepting PQ handshakes, both off by default:
  `handshakes.pq.initiate`, `handshakes.pq.accept`. `handshakes.pq.repair_delay` (default
  10ms) sets how long repair fragments trail the data fragments.
- Old nodes silently drop unknown subtypes, so discovery is speculative: an initiator with
  `initiate` enabled alternates PQ and classical attempts on successive retries, keeping
  both pending, and the first to complete wins.
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
  IPv6 /64, or relay channel), 16 KiB messages and a 3 s idle timeout.
- Tests: Noise-level KEM tests, codec and fragment tests and fuzzers, manager unit tests
  for the response budget and rate limit, and e2e tests for a clean handshake, loss of
  data fragments in both directions, fallback to a peer that does not accept PQ, a lost
  msg2 recovered by fresh symbols, sticky mode under an attacker dropping PQ packets,
  relays, and index cleanup on completion, fallback and timeout. ML-KEM and HKDF also
  pass under `GOEXPERIMENT=boringcrypto` and `GODEBUG=fips140=on`.

## Open items

1. Cookie wire format and the load threshold that triggers it.
2. Whether the decoder keeps spare symbols to identify injected symbols.
3. msg3 confirmation message format (phase 2).
4. Configuration reload: the `handshakes.pq` settings are read at startup only, like the
   rest of the `handshakes` section.
