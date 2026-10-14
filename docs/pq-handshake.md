# Post-quantum handshakes

Status: draft. Decisions below were made on 2026-10-13 (phase 1) and 2026-10-14 (phase 2); open
items are listed at the end. Both phases are implemented (see
[phase 1](#implementation-phase-1) and [phase 2](#implementation-phase-2)).

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

`crypto/mlkem` is available in Go 1.26; `crypto/mldsa` arrives in Go 1.27, which `go.mod`
requires since phase 2.

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

The `psk` token is the last in msg2, so the responder's static key `s` is encrypted under `ee` and
`se` only, and a future quantum attacker can read it from a recording; the certificate and indexes
follow the psk and stay protected. Identity hiding is a non-goal, and phase 2's KEM-first ordering
closes this anyway.

## Phase 2: hybrid IX with certificate v3

Phase 2 adds post-quantum authentication. Decisions were made on 2026-10-14; it is implemented on
the `pq-identity` branch (see [Implementation](#implementation-phase-2)).

### Certificate v3

A version 3 certificate is a version 2 certificate extended with post-quantum keys. It is its own
format, with its own PEM banner (`NEBULA CERTIFICATE V3`) and a strict parser, but its first
fields are exactly the fields of a v2 certificate:

```
CertificateV3 ::= SEQUENCE {
    details      [0] Details,        -- v2 details, unchanged
    curve        [1] Curve DEFAULT curve25519,
    publicKey    [2] OCTET STRING,   -- classical: X25519 / P256 for hosts, Ed25519 / ECDSA P256 for CAs
    signature    [3] OCTET STRING,   -- classical CA signature over details || curve || publicKey, as in v2
    pqPublicKey  [4] OCTET STRING,   -- ML-KEM-1024 encapsulation key for hosts, ML-DSA-87 public key for CAs
    pqSignature  [5] OCTET STRING    -- ML-DSA-87 by the issuing CA, context "nebula certificate v3",
                                     -- over the DER of fields 0 to 4, curve always present
}
```

- **The v2 form.** Fields 0 to 3 are a byte exact v2 certificate, signed by the v2 form of the CA.
  A v3 holder presents it in classical and phase 1 handshakes, so peers that only speak v2 accept
  it as they always have, and old parsers never see v3 bytes. A node therefore needs one
  certificate, not a v2 and v3 pair.
- **Signatures.** Both must verify. The ML-DSA-87 signature covers the classical signature too, so
  neither signature can be swapped out (which also makes P256 low/high-s alternates moot for v3).
  If ML-DSA fell classically and someone swapped `pqPublicKey`, the hybrid handshake still needs
  the classical static key, which only the classical signature covers. The ML-DSA-87 signature is
  deterministic (FIPS 204 section 3.4), so extending the same v2 certificate with the same key twice
  gives the same v3 certificate and fingerprint: `pq-extend` is idempotent. The hedged variant
  guards signers an attacker can fault physically, which a CA key in a file is not, and the Ed25519
  signature beside it is deterministic too.
- **Issuer and fingerprints.** The details are v2-shaped, so the issuer is the fingerprint of the
  CA's v2 form. A v3 certificate's own fingerprint is the SHA-256 of its whole encoding and differs
  from its v2 form's. Both identify it. To block a v3 certificate, block its v2 fingerprint: the
  pool checks it for the v3 certificate and for its v2 form alike, so one entry covers both forms,
  while blocking only the v3 fingerprint leaves the v2 form usable in classical handshakes.
  `nebula-cert print` leads with both fingerprints and says which one to block. Firewall `ca_sha`
  rules match a v3 peer by either fingerprint of its CA.
- **CA pool.** A v3 CA verifies only v3 certificates. To accept v2 certificates as well the pool
  must also list the CA's v2 form. Dropping the v2 form is how a node requires post-quantum
  authentication; there is no separate setting. Two different v3 extensions of one v2 CA are
  rejected as ambiguous.
- **Keys are composite**, classical followed by post-quantum, wherever a v3 certificate deals in
  them: `PublicKey()` returns `classical || pq`, and private keys are `classical || seed` (64 byte
  ML-KEM seed for hosts, 32 byte ML-DSA seed for CAs), in one PEM block in `pki.key` with banners
  such as `NEBULA X25519 MLKEM1024 PRIVATE KEY` and `NEBULA ED25519 MLDSA87 PRIVATE KEY`.
- **Both curves.** Curve25519 and P256; the post-quantum half does not depend on the curve.
- **In-place upgrade.** `nebula-cert pq-extend` turns an existing v2 CA into a v3 CA whose v2 form
  is the old CA certificate, byte for byte, and extends existing host certificates the same way.
  Fingerprints, blocklists and trust in the v2 forms carry over unchanged. Hosts get their ML-KEM
  key with `nebula-cert keygen -in-key`, which keeps the classical key.

| Certificate | Full | In a handshake | v2 form |
|---|---|---|---|
| CA, Curve25519 | 7362 B | n/a | 134 B |
| Host, Curve25519 | 6375 B | 4769 B | 171 B |

`crypto/mldsa` is new in Go 1.27, so `go.mod` moves to Go 1.27.

### Handshake

A new subtype, `ix_hybrid_mlkem1024` (3), runs `HandshakeHybridIX` from
[github.com/DefinedNet/noise](https://github.com/DefinedNet/noise) (its `PQ_RESEARCH.md` gives the
design rationale and security argument), with ML-KEM-1024 supplied by nebula:

```
-> e, s
<- ekem, skem, e, ee, se, s, es
-> skem
```

- `e` and `s` carry composite keys, X25519 (or P256) followed by ML-KEM-1024. DH tokens use the
  classical halves, `ekem` and `skem` encapsulate to the ML-KEM halves, and every secret goes into
  the one chaining key.
- **The responder's `e` is classical only.** It follows the responder's `ekem`, which already
  completed the ephemeral KEM exchange, so it carries only the X25519 (or P256) key that `ee` and
  `se` need. A second ephemeral KEM exchange would add nothing: one `ekem` is lost only if the
  initiator's ephemeral private key or the responder's encapsulation randomness is, and a reverse
  one would be lost in the same cases. PQNoise's pqIX has no responder `e` at all. The static ML-KEM key is the post-quantum half of the certificate's public
  key, so it travels in `s` and the handshake form of the certificate leaves out both keys.
- **KEM tokens first.** msg2 starts with `ekem, skem`, so the responder's static key and
  certificate are encrypted under keys that already include both KEM secrets: the responder's
  identity is protected against harvest-now-decrypt-later, as TLS 1.3 with `X25519MLKEM768`
  protects the server certificate. (OpenSSH offers no comparison: its hybrid key exchange sends the
  host key in the clear.) The initiator's certificate travels in msg1 in the clear, as in IX today.
- **Authentication.** The responder authenticates the initiator when msg3 decrypts (it depends on
  msg2's `skem` to the initiator's static key); the initiator authenticates the responder when the
  first packet under the new keys decrypts (it depends on msg3's `skem`). Neither side needs a
  signature. Knowing only a peer's classical private key gets an impersonator nowhere: as an
  initiator it cannot read msg2, as a responder it cannot read msg3.
- **The two static ML-KEM keys see different ciphertexts.** msg2's `skem` ciphertext is encrypted
  under a key derived from the `ekem` secret, which whoever sent msg2 chose, so anyone who can
  address a pending initiator's index can have the initiator decapsulate a ciphertext of their
  choosing with its static key. That is the IND-CCA setting ML-KEM is designed for, and
  `crypto/mlkem` is constant time. The responder decrypts msg3's `skem` ciphertext under the keys of
  a completed msg2 before decapsulating, so it only ever decapsulates ciphertexts the genuine
  initiator sealed.
- v3 certificates go with this subtype and nothing else: a v3 certificate on any other subtype, or
  a v2 one on this one, is a protocol error.

| Message | Size (Curve25519) | Data fragments (k) |
|---|---|---|
| msg1 | 8006 B | 7 |
| msg2 | 9625 B | 9 |
| msg3 | 1616 B | 2 |

**Dependency.** DefinedNet/noise is a private repository today. `go.mod` points at a local clone
with a `replace` directive; the module has to be published (or the hybrid patterns upstreamed to
flynn/noise) before this can merge.

### Three messages in the manager

- **Responder.** After msg2 the responder keeps the handshake pending under its local index, the
  multi-message responder the manager lacked before. A repeated msg1 maps to it through the
  answered-msg1 cache and gets msg2 resent with fresh symbols, as in phase 1. msg3's fragments name
  the responder's index, so they reach the pending entry and never the pre-authentication table;
  its reassembly is capped at 4 KiB. Until msg3 verifies, data for that index is dropped quietly:
  a RecvError would tear down the initiator's new tunnel. On completing, the responder sends an
  empty `Test`/`TestReply` under the new keys so the initiator hears back without traffic. A
  pending responder expires after the handshake timeout.
- **Initiator.** Writing msg3 yields the transport keys, so the tunnel goes live at once, readable
  only by the real responder; msg3 goes out before any packets cached during the handshake. Until
  anything from the responder decrypts on the new tunnel, msg3 is resent with fresh symbols on a
  linear backoff, and if nothing has decrypted by the handshake timeout the tunnel is closed.
  Losing msg3 costs the data sent right behind it, which the overlay retransmits.
- **Lost confirmation.** A msg3 fragment for a v3 tunnel the responder already completed means the
  initiator is still waiting, so the responder confirms again, at most once per retry interval and
  only to the tunnel's own remote, never to the fragment's source.
- **Crossing attempts.** The initiator's classical attempt can reach the responder, which
  completes it at once, while the hybrid handshake still waits for msg3. If the initiator got the
  hybrid msg2 first it has committed to hybrid and sends msg3, so the responder takes the hybrid
  tunnel even though the classical one is newer, rather than rejecting it as too old.
- **A failed attempt.** A post-quantum attempt can fail fatally where the classical one would not,
  for example a v3 certificate from a CA the initiator trusts only in its v2 form. The failed
  attempt is dropped and the handshake continues classical. With `require` the handshake ends.

### Rollout with v3

- A node with a v3 certificate initiates hybrid handshakes in place of phase 1 ones, alternating
  with classical as before. It never initiates phase 1, but still answers phase 1 handshakes with
  its v2 form, so a peer with only a v2 certificate gets a classical tunnel from it.
- A responder without a v3 certificate drops hybrid msg1s before reassembly.
- `handshakes.pq.require` with a v3 certificate means hybrid only, in both directions: phase 1
  msg1s are dropped too, so every peer needs a v3 certificate.
- Post-quantum authentication is required through the CA pool, by not listing the CA's v2 form.
  A sticky or `require` initiator resists active downgrade of the key exchange; only the CA pool
  resists downgrade of authentication, since a quantum attacker could forge a v2 form.
- `sticky` stays off by default for v3 holders too (decided 2026-10-14): a peer re-issued back to a
  v2-only certificate would otherwise be unreachable until this process restarts. Deployments that
  want downgrade resistance turn on `sticky` or `require`, or drop the CA's v2 form from the pool.

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
- A completed message the responder answered is remembered without its symbols, outside the
  memory and per-source caps, for the idle timeout: which symbol indexes it has seen, and its
  hash. Fragments still trailing the attempt that completed it are counted and dropped. Once as
  many new symbols as it has data symbols arrive, which only a retry offers, it is reported as a
  repeat and the cached response is resent. Without this, the repair fragments trailing a msg1
  whose data fragments already completed it open an entry that for K above the repair count can
  never complete, and back to back handshakes from one source run into its quota (seen on real
  hosts: the fifth hybrid handshake within 3 s fell back to classical). A message that decoded
  but was not answered is forgotten, and the next attempt rebuilds it.
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
  the responder; the responder sends a small confirmation on completion and drops tunnel
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

#### Pending hybrid responders

A hybrid responder that answered msg1 keeps a pending entry, keyed by its local index, until
msg3 arrives or the handshake timeout (5.5 s by default) passes. msg1 is cleartext and nothing
covers `e` or `Time`, so from one captured v3 msg1 an attacker can mint distinct valid msg1s
with a fresh `e` and a bumped `Time`. Each misses the answered-msg1 cache, costs the responder
the whole msg1 (two signature verifications, two encapsulations, four DH operations, the
certificate checks) and a pending entry, and the fragment table stays near empty because a
complete burst arrives together, so cookies are never demanded and spoofed sources work.
Pending entries are not bounded per peer or in total. Accepted as is (2026-10-14): the per-msg1
work is the same class as classical IX's pre-authentication cost, the expiry bounds the state in
time and the fragment table bounds bytes in flight. If it needs tightening, cap pending
responders per certificate fingerprint and in total, and count them toward the cookie
threshold.

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

## Implementation (phase 2)

- `cert`: `cert_v3.go` (format, `V2Form`, `ExtendToV3`, `SignPQ`), `SignHybridWith` and the
  composite `Sign` path, the CA pool's v3 index and v2-form blocklisting, and the composite key
  PEM banners.
- `handshake`: the `ix_hybrid_mlkem1024` subtype on `noise.HandshakeHybridIX`, `KEMMLKEM1024`,
  composite credentials, cipher states ordered by role for three message patterns, and
  `Machine.PeerCert` for a responder that has to act before completion.
- `pki.go` loads a v3 certificate with its composite key and derives the v2 form; messages after
  the handshake treat v3 tunnels as v2 (`protocolVersion`).
- `handshake_manager_hybrid.go`: pending responders, confirmation and reconfirmation, and the
  initiator's msg3 resends and teardown; `outside.go` keeps quiet about pending responder indexes.
- `nebula-cert`: `ca`, `keygen` and `sign` take `-version 3`, `keygen -in-key` extends an existing
  host key, `sign -version 2` with a v3 CA signs as its v2 form, and `pq-extend` upgrades v2
  certificates in place, keeping an encrypted CA key encrypted.
- Tests: certificate format, strictness, tampering, pool and blocklist rules and in-place
  extension on both curves; Machine-level hybrid handshakes including corrupted msg3 and
  impersonation with only the classical key; e2e tests for a clean hybrid handshake, a lost
  confirmation, a never confirmed handshake (no RecvErrors, teardown, expiry), a v2-only peer, an
  initiator that trusts only the v2 form, `require` both ways, and relays; pki loading; firewall
  `ca_sha`; and the `nebula-cert` flows.

## Open items

- Publish DefinedNet/noise and drop the `replace` in `go.mod`, once Nate says the fork is ready to
  ship. The classical-only responder `e` is on the local clone's `drop-responder-ekem-key` branch
  (b4a892b), not yet in DefinedNet/noise.
- DefinedNet/noise `ReadMessage` returns `ErrShortMessage` without rolling back the symmetric
  state ([DefinedNet/noise#2](https://github.com/DefinedNet/noise/issues/2), inherited from
  flynn/noise). A message that fails a length check after a key-mixing token leaves `ck` and `h`
  advanced, so the genuine message can never be read: one spoofed short packet to a pending
  initiator's index, which msg1 carries in the clear in every IX variant, kills that attempt until
  it times out, and the Machine reports it as recoverable. Blocks publishing the module; the fix is
  a deferred rollback that also restores `k`, `n` and `hasK`. Smaller pre-publish items are in
  [DefinedNet/noise#3](https://github.com/DefinedNet/noise/issues/3).
- Field test of hybrid handshakes on real hosts, as was done for phase 1.

The cryptographic review of 2026-10-14 found no break in the composition or the certificate
chain. Its outcomes are folded in above: deterministic ML-DSA signing, the fingerprint guidance,
the `skem` oracle note, the psk2 note, the pending-responder exposure and the `sticky` default.

Accepted as is: a tunnel that came up classical between two v3 holders (say, the hybrid attempt
was dropped) stays classical until it rehandshakes for another reason. `require`, `sticky` and a
CA pool without v2 forms cover deployments that need more. PKCS#11 keys do not support v3.
