# Post-quantum handshakes

Status: draft. Decisions below were made on 2026-10-13 and 2026-10-14; open items are listed at
the end. Post-quantum handshakes ship hybrid only, on version 3 certificates (decided
2026-10-14); see [Implementation](#implementation-certificates-and-the-hybrid-handshake).

## Goals

1. **Confidentiality against harvest-now-decrypt-later.** Traffic recorded today must stay
   secret after a cryptographically relevant quantum computer exists. This needs a
   post-quantum key exchange now.
2. **Post-quantum authentication.** Needs certificates whose CA signature and host keys are
   post-quantum, so certificates have to be reissued or extended. Post-quantum key exchange
   ships only together with it: there is no post-quantum handshake on version 2 certificates.
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
requires.

## An ephemeral-KEM handshake, built and dropped

The first design was `ix_psk2_mlkem1024`: classical IX on version 2 certificates with an ephemeral
ML-KEM-1024 exchange mixed in through the `psk2` slot, so recorded traffic was protected without
reissuing certificates. It was built, field tested and then dropped on 2026-10-14, before any
release. Post-quantum handshakes ship hybrid only, for three reasons:

- It left authentication classical, which a deployment wanting quantum safety needs anyway, and
  a second post-quantum handshake would be twice the code to review and keep.
- It completes in two messages, so the responder could not tell which of two crossing attempts
  the initiator kept (see [Crossing attempts](#three-messages-in-the-manager)); on real hosts 5 of
  100 first pings failed at 50 ms round trip for that reason.
- Its `psk` token came last in msg2, so the responder's static key travelled under classical keys
  only.

Subtype 2 and payload field 9 (its encapsulation key) stay reserved. The code is on the
`pq-handshake` branch for reference.

## Hybrid IX with certificate v3

Decided on 2026-10-14 and implemented on the `pq-identity` branch (see
[Implementation](#implementation-certificates-and-the-hybrid-handshake)).

### Certificate v3

A version 3 certificate is a version 2 certificate's fields extended with post-quantum keys. It
is its own format, with its own PEM banner (`NEBULA CERTIFICATE V3`) and a strict parser.
[`cert/cert_v3.asn1`](../cert/cert_v3.asn1) defines the wire format: the fields of a v2
certificate (0 to 3, the v2 signature optional), followed by `pqSuite`, `issuer`, `pqPublicKey`,
`classicalSignature` and `pqSignature` (4 to 8). There is no extension point: anything new is a
new suite or version, which a parser refuses rather than skips.

- **The suite.** `pqSuite` names the post-quantum algorithms the way `curve` names the classical
  ones: the KEM of host keys, and the signature algorithm of CA keys and of the certificates a CA
  signs. A CA and every certificate it signs share a suite, as they share a curve; the CA pool
  rejects a mismatch, and the post-quantum signature covers the suite, so a certificate can not be
  relabelled. The field is always present, in handshakes too, with no default, and 0 is never
  valid. There is one suite today, `MLKEM1024_MLDSA87` (1): ML-KEM-1024 hosts, ML-DSA-87 CAs. A
  new suite is an entry in the cert package's suite table plus, for a new KEM, a hybrid subtype; no
  new certificate version. Changing a CA's suite means a new CA, or a new v3 extension of its v2
  form.

- **The v2 form, optional.** With the v2 signature present, fields 0 to 3 are a byte exact v2
  certificate, signed by the v2 form of the CA. A v3 holder presents it in classical handshakes,
  so peers that only speak v2 accept it as they always have, and old parsers never see v3 bytes.
  A node therefore needs one certificate, not a v2 and v3 pair. Without the v2 signature the
  details name no issuer either, and the certificate has no v2 form: it is for v3 peers only,
  100 bytes smaller in every handshake (66 for the signature, 34 for the issuer, on Curve25519).
  The CA decides which: both signatures of the whole certificate cover the v2 signature and the
  details, so a v2 form can not be stripped or added by anyone else, and a CA without a v2 form
  of its own can not issue certificates with one. A v2 form is for migrating; once every peer
  has a v3 certificate, the CA reissues certificates without one.
- **Signatures.** A v3 certificate carries three, and all must verify: the v2 form's own classical
  signature, and a composite signature of the whole certificate, one classical and one ML-DSA-87
  signature by the issuing CA's two keys. Both halves sign the same message, built as in
  [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/):
  `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)`, with its Prefix, a label naming
  the pair of algorithms (`NEBULA-CERTV3-MLDSA87-Ed25519-SHA512`, `NEBULA-CERTV3-MLDSA87-ECDSA-P256-SHA512`),
  `ctx = "nebula certificate v3"`, and M every field but the two, the v2 form's signature included.
  ML-DSA also gets the label as its context. So every field is covered by both a classical and a
  post-quantum signature, and the certificate stays sound while either algorithm does. That
  includes a CA's own extension, which both of its keys sign: holding the public v2 CA certificate
  and an ML-DSA key of one's own is no longer enough to mint a look-alike v3 CA.
- **Composite, but not draft-ietf-lamps-pq-composite-sigs's.** draft-ietf-lamps-pq-composite-sigs
  registers no pair of ML-DSA-87 with Ed25519 or ECDSA P256 and allows only its own labels (§2.2),
  so the labels are nebula's and the signatures are not interoperable with its. It also forbids
  using a component key outside its composite (§3.1, §5.3, §9.3), while the classical CA key here
  also signs every v2 form and v1 certificate. The prefix is what keeps those apart: every v3
  signed message starts with it, no v1 or v2 signing input does, so no signature can be taken for
  one of another kind (the guard of its §9.4). §9.3 leaves the soundness of such reuse to
  per-application analysis; this is ours.
- **One encoding.** The ML-DSA-87 signature and both classical ones are deterministic (FIPS 204
  section 3.4, Ed25519, and RFC 6979 for ECDSA P256), so extending the same v2 certificate with the
  same keys twice gives the same v3 certificate and fingerprint. `pq-extend` is idempotent for
  host certificates, whose post-quantum key comes from `keygen -in-key`. A CA's post-quantum key is
  new on every run unless `-in-pq-key` hands it the v3 key of an earlier run, and is never derived
  from the classical key, which would give it to whoever breaks the classical one. A P256
  signature of the whole certificate must be low-s, since nothing covers it and the high-s form
  would give the certificate a second fingerprint; the v2 form's is covered by both. The hedged
  ML-DSA variant guards signers an attacker can fault physically, which a CA key in a file is not.
- **Issuer and fingerprints.** The details are v2-shaped, so the v2 form's issuer is the fingerprint
  of the CA's v2 form. The v3 certificate names its own issuer, the fingerprint of the v3 CA, so the
  signatures bind it to that CA's keys, both of them, rather than only to the v2 CA it extends.
  The pool finds a v3 certificate's CA by that issuer and requires the two issuers to agree: the v2
  form's must be the found CA's v2 form. A v3 certificate's own fingerprint is the SHA-256 of its whole encoding and differs
  from its v2 form's. Both identify it. To block a v3 certificate, block its v2 fingerprint: the
  pool checks it for the v3 certificate and for its v2 form alike, so one entry covers both forms,
  while blocking only the v3 fingerprint leaves the v2 form usable in classical handshakes.
  `nebula-cert print` leads with both fingerprints and says which one to block. Firewall `ca_sha`
  rules match a v3 peer by either fingerprint of its CA.
- **CA pool.** A v3 CA verifies only v3 certificates. To accept v2 certificates as well the pool
  must also list the CA's v2 form, which a CA without one can not offer. A certificate with a v2
  form must name, in its details, the v2 form of the CA that signed it. Dropping the v2 form is how a node requires post-quantum
  authentication; there is no separate setting. Two v3 extensions of one v2 CA, with different
  ML-DSA keys, are different CAs: each verifies only the certificates it issued, and both can be
  trusted at once, say while moving hosts to a new post-quantum CA key.
- **Keys are composite**, classical followed by post-quantum, wherever a v3 certificate deals in
  them: `PublicKey()` returns `classical || pq`, and private keys are `classical || seed` (64 byte
  ML-KEM seed for hosts, 32 byte ML-DSA seed for CAs), in one PEM block in `pki.key` with banners
  such as `NEBULA X25519 MLKEM1024 PRIVATE KEY` and `NEBULA ED25519 MLDSA87 PRIVATE KEY`. The
  banner names the post-quantum algorithm, not the suite, because a seed's size does not tell the
  algorithm's strength.
- **Both curves.** Curve25519 and P256; the post-quantum half does not depend on the curve.
- **In-place upgrade.** `nebula-cert pq-extend` turns an existing v2 CA into a v3 CA whose v2 form
  is the old CA certificate, byte for byte, and extends existing host certificates the same way.
  Fingerprints, blocklists and trust in the v2 forms carry over unchanged. Hosts get their ML-KEM
  key with `nebula-cert keygen -in-key`, which keeps the classical key. Extending a CA again with
  `-in-pq-key`, its v3 key from the first run, gives the same v3 CA; without it, a different one.

| Certificate, Curve25519 | Full | In a handshake | v2 form |
|---|---|---|---|
| CA with a v2 form | 7426 B | n/a | 128 B |
| CA without | 7365 B | n/a | none |
| Host with a v2 form | 6473 B | 4867 B | 166 B |
| Host without | 6373 B | 4767 B | none |

`crypto/mldsa` is new in Go 1.27, so `go.mod` moves to Go 1.27.

#### Classical key reuse

A CA whose v3 certificate carries a v2 form signs with one classical key in two roles: standalone
v1 and v2 certificates, the v2 forms among them, and the classical half of every v3 composite
signature. draft-ietf-lamps-pq-composite-sigs forbids exactly this (§3.1, §5.3): "key reuse MUST
be avoided to prevent the introduction of EUF-CMA vulnerabilities" (§9.3), the stripping attacks
of §9.2 being the main one. Its §9.3 leaves any mitigation to "per-application security
analysis". This is ours. In short, reuse costs no cryptographic security; its cost is operational.

What the classical CA key signs:

| Context | Signed bytes | First byte | Verifier |
|---|---|---|---|
| v1 certificate | `proto.Marshal(RawNebulaCertificateDetails)` | the lowest field present, which the required public key (field 7) bounds: `0x0a` `0x12` `0x1a` `0x22` `0x28` `0x30` or `0x3a` | re-encodes the parsed details |
| v2 certificate, v2 form | `rawDetails ‖ curve ‖ publicKey` | `0xa0`, the parser requires the `[0]` details element | raw bytes, constrained to start with it |
| v3 composite, classical half | `M' = "CompositeAlgorithmSignatures2025" ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M)` | `0x43` | builds M' itself |

The three message spaces are disjoint, since no first byte is shared. Protobuf encodes fields in
number order, so a v1 message starts with the tag of its lowest field, and every v1 certificate
has a public key, field 7, which `validate` requires when signing and parsing alike: a v1 message
starts at or below its tag, `0x3a`, never with v2's `0xa0` (field 100, the curve, could only lead
a message with no field below it) or v3's `0x43` (field 8 with wire type 3, start group, which
the bool field 8 never takes). `TestCASigningInputsAreDisjoint` pins all of it. A signature made in one context therefore never verifies for the same bytes in another, and
Ed25519 and ECDSA are EUF-CMA under one key whatever mix of messages it signs: signatures on v1
and v2 messages give no signature on any M', since no v1 or v2 message is one. Stripping (§9.2)
needs a standalone verifier that accepts `(M', tradSig)`, and nebula's only standalone verifiers
are the v1 and v2 certificate checks, which reject a message starting with `0x43`: the prefix
guard of §9.4, built in.

| Scenario | Reused classical key | Fresh v3 CA key |
|---|---|---|
| nothing broken | sound | sound |
| a CRQC breaks classical crypto | v2 forms forgeable while the v2 CA is trusted; composite holds on ML-DSA | the same: a CRQC recovers any classical key |
| ML-DSA broken classically | composite holds on the classical half, given the disjoint messages above | composite holds on the classical half |
| both broken | lost | lost |
| the classical CA key is stolen | every v3 composite falls to ML-DSA alone, and the v3 CA retires with the v2 one | v3 untouched, only v2 falls |

Theft is the only row where they differ, and there reuse degrades the composite to one algorithm
rather than breaking it. It matters because a v2 CA key is old and has had years to be copied into
backups, laptops and issuing systems.

The argument rests on four conditions:

- **C1.** The classical CA key signs nebula certificates and nothing else. Nothing in nebula can
  enforce this: an HSM slot or signing service that also signs other bytes for it falls outside
  the table. It is a rule for whoever runs the CA.
- **C2.** Every future CA-signed format stays disjoint from the table, or carries its own prefix.
  `TestCASigningInputsAreDisjoint` pins the table, deriving v1's first bytes from its protobuf
  descriptor and the public key it requires, so a new format has to be added to it.
- **C3.** Verifiers build or constrain the signed message rather than taking it from the caller,
  as all three do.
- **C4.** SHA-256 and SHA-512 are collision resistant: ECDSA P256 signs SHA-256 of each message,
  and M' carries SHA-512(M).

Two smaller points. On P256 the same key signs with random nonces (v1, v2) and RFC 6979
deterministic ones (v3), which is safe, since neither repeats a nonce across messages. Ed25519 is
pure Ed25519 in every context, never mixed with Ed25519ctx or Ed25519ph.

TLS 1.3 accepted the same reuse for the same reason: one certificate key signs in TLS 1.2 and
TLS 1.3, and RFC 8446 §4.4.3 prefixes every TLS 1.3 signature with 64 spaces and a context string,
"used to provide separation between signatures made in different contexts, helping against
potential cross-protocol attacks". The M' prefix and ctx do that job here.

Host keys reuse too: a host's classical X25519 or P256 static key serves classical IX and
`IXhybrid` handshakes alike, whichever certificate design is used. The Noise specification
(revision 34, §14, "Static key reuse") allows a static key pair to be used "with different Noise
protocols, provided the same hash algorithm is used in all of them". Both handshakes use SHA-256,
and their protocol names differ, `Noise_IX_…` and `Noise_IXhybrid_…`, so their transcripts never
meet. `IXhybrid` comes from the DefinedNet/noise fork, not revision 34, so counting it among
Noise protocols is our reading.

So interop CAs are allowed, and nothing in code forbids reuse: it would buy no cryptographic
security and would rule out migrating through an interop CA. Once v2 is gone, a fresh v3 CA with
no v2 form shrinks the blast radius of a stolen key and leaves the network within
draft-ietf-lamps-pq-composite-sigs's own model instead of this argument.

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
- **One subtype per KEM.** A hybrid subtype names its KEM, and a v3 holder initiates the subtype of
  its suite's KEM. Peers need the same KEM, not the same suite: suites that differ only in their
  signature algorithm share a subtype, and each certificate carries its own suite. A responder
  whose suite uses another KEM drops msg1, so the pair behaves as if the responder did not speak
  PQ: classical fallback, or no tunnel under `require`. A suite's KEM must have a subtype for the
  pki to load a certificate in it.

Sizes depend on the certificates, since msg1 carries the initiator's and msg2 the responder's. A
data fragment holds up to 1160 bytes, so msg1 needs 8 once it passes 8120 bytes, which nearly every real
certificate does: a single group of 8 bytes on the minimal Curve25519 one is enough. The minimal
certificate has a 9 byte name, no groups and one IPv4 network; the typical one a 35 byte name,
three groups (`prod`, `web`, `ssh-admins`) and an IPv4 and an IPv6 network.

| Message | Minimal, Curve25519 | Typical, Curve25519 | Minimal, P256 | Typical, P256 |
|---|---|---|---|---|
| msg1 | 8109 B, k=7 | 8180 B, k=8 | 8187 B, k=8 | 8259 B, k=8 |
| msg2 | 9728 B, k=9 | 9799 B, k=9 | 9807 B, k=9 | 9878 B, k=9 |
| msg3 | 1616 B, k=2 | 1616 B, k=2 | 1616 B, k=2 | 1616 B, k=2 |

Each byte of name or group adds about a byte to the message carrying the certificate, and each group
two more. msg2 has room to spare at 9 fragments, up to 10440 bytes.

**Dependency.** DefinedNet/noise is a private repository today. `go.mod` points at a local clone
with a `replace` directive; the module has to be published (or the hybrid patterns upstreamed to
flynn/noise) before this can merge.

### Three messages in the manager

- **Responder.** After msg2 the responder keeps the handshake pending under its local index, the
  multi-message responder the manager lacked before. A repeated msg1 maps to it through the
  answered-msg1 cache and gets msg2 resent with fresh symbols. msg3's fragments name
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
- **Crossing attempts.** The initiator alternates, and its first classical attempt follows the
  hybrid msg1 anywhere from right away to three retry intervals later (the retry timer lands two
  slots ahead on the timer wheel, which moves on whole ticks), so at real round-trip times it
  often goes out before msg2 is back. Answered, it would complete at once on the responder while
  the hybrid handshake waits for msg3. So for four retry intervals after answering a peer's new
  hybrid msg1, the responder leaves that peer's classical msg1s unanswered: the crossing one
  arrives within the window whatever the round trip, because both take the same path. The
  window is short so an initiator whose hybrid attempt fails on its own side (one that does not
  yet trust our v3 CA, during a rollout) still gets a classical answer to a later attempt; a
  block lasting as long as the hybrid state would refuse it until its handshake timed out, and
  its next handshake would start with a hybrid msg1 again. A classical msg1 that still crosses,
  past the window on a very slow path, is answered, but msg3 settles it: the initiator only
  sends msg3 after committing to hybrid, so the responder takes the hybrid tunnel even though
  the classical one is newer, rather than rejecting it as too old.
- **A failed attempt.** A post-quantum attempt can fail fatally where the classical one would not,
  for example a v3 certificate from a CA the initiator trusts only in its v2 form. The failed
  attempt is dropped and the handshake continues classical. With `require` the handshake ends.

### Rollout with v3

- `handshakes.pq` only does anything on a node with a v3 certificate. Without one, `initiate`,
  `accept` and `sticky` log a warning and are ignored, and `require` is refused at startup and
  on reload, since such a node could reach no one.
- A build without ML-DSA, under the FIPS 140-3 Go Cryptographic Module v1.0.0, can not verify v3
  certificates. It leaves v3 CAs out of its CA pool with a warning rather than failing to load the
  pool, so a CA bundle shared with v3 nodes keeps working for it, and it stays classical. Its tests
  skip whatever needs ML-DSA. A v3 certificate of its own fails to load, with the module's error.
- A node whose v3 certificate has no v2 form holds nothing to answer a classical handshake with,
  so it speaks hybrid handshakes only, as if `require` were set, whatever `handshakes.pq` says.
  Such a certificate stands alone in `pki.cert`: no v1 or v2 certificate beside it. The node
  initiates as version 3, which is also the only `pki.initiating_version` it accepts, and peers
  with only a v2 certificate can not reach it. Lighthouses and relays keep a v2 form for as long
  as any node they serve lacks a v3 certificate.
- A responder without a v3 certificate, or whose suite uses another KEM, drops hybrid msg1s
  before reassembly, and the initiator falls back to classical.
- `handshakes.pq.require` means hybrid only, in both directions, so every peer needs a v3
  certificate.
- Post-quantum authentication is required through the CA pool, by not listing the CA's v2 form.
  A sticky or `require` initiator resists active downgrade of the key exchange; only the CA pool
  resists downgrade of authentication, since a quantum attacker could forge a v2 form.
- `sticky` stays off by default for v3 holders too (decided 2026-10-14): a peer re-issued back to a
  v2-only certificate would otherwise be unreachable until this process restarts. Deployments that
  want downgrade resistance turn on `sticky` or `require`, or drop the CA's v2 form from the pool.

## Fragment transport

Hybrid messages travel as fragmented handshakes, described in
[fragmented-handshakes.md](fragmented-handshakes.md): the wire format, the erasure code, the
receiver rules, the amplification budget and the cookies are the ones a classical message too big
for one packet uses. A hybrid message is always fragmented. Its subtype on the wire is
`ix_hybrid_mlkem1024 | 0x80`, `handshakes.fragment` does not apply to it (under `never` a node
still sends and reassembles hybrid fragments, there being no other way for them to go), and an
unfragmented hybrid message is dropped. What hybrid adds:

- **msg3.** Its fragments (Counter 3) name the responder's index, so they reach the pending
  responder and never the pre-authentication table. Its reassembly is capped at 4 KiB and checks
  FragID against the initiator's index learned from msg1. msg3 goes out without a repair delay:
  the packets cached during the handshake follow right behind it, and the responder drops
  whatever arrives before msg3 completes, so a trailing repair would cost them whenever a data
  fragment is lost. msg3 is four packets, too short for the tail drop the delay guards against.
- **The initiator's post-quantum attempt** has its own fragment sender, msg2 slots and cookie,
  under its own local index, which is its FragID. A msg2 fragment or cookie reply for it shows
  the peer speaks post-quantum (see [Rollout](#rollout)).
- **Before reassembly**, a responder that does not accept post-quantum handshakes, has no v3
  certificate, or whose suite uses another KEM drops a hybrid msg1.
- **Repeats.** A pending responder still holds its index, so a repeated msg1 is answered with its
  cached msg2 while it waits for msg3, as an established tunnel's is.
- **Per-path resends** of a cached msg2 mean a recently answered msg1 replayed from spoofed
  sources draws one cached msg2 to each, at about 1.2-1.4x the bytes sent and never over 3x, for
  as long as the answered msg1 is remembered (the handshake timeout). Accepted (2026-10-15):
  classical IX already resends its stored msg2 to any source that replays msg1, with no clock at
  all, and a per-handshake clock is what broke a path that only works one way.
- **Injected symbols** can stop a fragmented handshake where they could not stop an unfragmented
  one. A non-sticky initiator still gets a classical tunnel from its next attempt; a sticky one,
  by design, does not downgrade.

### Pending hybrid responders

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

## Rollout

- Separate settings for initiating and accepting PQ handshakes, both off by default:
  `handshakes.pq.initiate`, `handshakes.pq.accept`. `handshakes.repair_delay` (default 10ms),
  shared with every fragmented handshake, sets how long repair fragments trail the data fragments.
- `handshakes.pq.require` makes every handshake PQ: it implies `initiate` and `accept`,
  never offers a classical attempt, and drops classical msg1s. It needs a v3 certificate.
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
| two messages (2, 2) no FEC | 5% | 81.4% | 85.6% | 87.9% | 89.0% |
| two messages (2, 2) FEC | 5% | 99.9% | 99.4% | 99.3% | 98.6% |
| two messages (2, 2) FEC | 10% | 99.3% | 97.5% | 97.4% | 96.3% |
| hybrid (7, 9, 2) no FEC | 5% | 39.8% | 57.5% | 70.4% | 77.7% |
| hybrid (7, 9, 2) FEC | 5% | 99.6% | 94.2% | 90.4% | 88.8% |
| hybrid (7, 9, 2) FEC | 10% | 95.9% | 84.6% | 79.0% | 77.3% |

With fresh repair symbols, the hybrid handshake completes within two attempts at least 99.1% of the time
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

## Implementation: the manager

- The fragment transport is `handshake/fec`, `handshake/fragment` and
  `handshake_manager_fragment.go`, shared with classical handshakes (see
  [fragmented-handshakes.md](fragmented-handshakes.md)). It routes hybrid fragments to the
  post-quantum attempt and to pending responders.
- `handshake_manager_pq.go`:
  - **Initiator.** Attempts alternate PQ and classical, starting with PQ (sticky peers get
    only PQ). The PQ attempt has its own local index registered alongside the classical
    one; whichever response completes first wins, and the other index is released
    (`settleIndex`). A timed out or deleted pending handshake releases both. A relay that
    comes up pushes the pending attempt through it at once (`relayEstablished`).
  - **Settings.** `handshakes.pq` is loaded and reloaded here, and `require` drops classical
    msg1s, fragmented or not.
- Tests: manager unit tests for the attempt's cookie and msg2 routing, alternation, reload,
  `require` and the crossing window, and e2e tests for a clean handshake, loss of data fragments
  in both directions, fallback to a peer that does not accept PQ, a lost msg2 recovered by fresh
  symbols, sticky mode under an attacker dropping PQ packets, relays, a direct msg2 lost on every
  attempt and answered through a relay instead, index cleanup on completion, fallback and
  timeout, and a responder flooded from spoofed sources demanding and accepting a cookie. ML-KEM
  also passes under `GOEXPERIMENT=boringcrypto` and `GODEBUG=fips140=on`.

## Implementation: certificates and the hybrid handshake

- `cert`: `cert_v3.go` (format, `V2Form`, `ExtendToV3`, `SignPQ`), `pq_suite.go` (`PQSuite` and
  the suite table), `SignHybridWith` and the composite `Sign` path, the CA pool's v3 index, suite
  check and v2-form blocklisting, and the composite key PEM banners, generated per suite.
- `handshake`: the `ix_hybrid_mlkem1024` subtype on `noise.HandshakeHybridIX`, `KEMMLKEM1024`,
  `HybridSubtype` mapping a suite to the subtype of its KEM,
  composite credentials, cipher states ordered by role for three message patterns, and
  `Machine.PeerCert` for a responder that has to act before completion.
- `pki.go` loads a v3 certificate with its composite key and derives the v2 form; messages after
  the handshake treat v3 tunnels as v2 (`protocolVersion`).
- `handshake_manager_hybrid.go`: pending responders, confirmation and reconfirmation, the
  initiator's msg3 resends and teardown, and the crossing window; `outside.go` keeps quiet about
  pending responder indexes.
- `nebula-cert`: `ca`, `keygen` and `sign` take `-version 3`, `keygen -in-key` extends an existing
  host key, `sign -version 2` with a v3 CA signs as its v2 form, and `pq-extend` upgrades v2
  certificates in place, keeping an encrypted CA key encrypted. `ca`, `keygen` and `pq-extend` of a
  CA take `-pq-suite`; `sign` and `pq-extend` of a host take the CA's suite.
- Tests: certificate format, strictness, tampering, pool and blocklist rules and in-place
  extension on both curves; Machine-level hybrid handshakes including corrupted msg3 and
  impersonation with only the classical key; e2e tests for a clean hybrid handshake, a lost
  confirmation, a never confirmed handshake (no RecvErrors, teardown, expiry), a v2-only peer, an
  initiator that trusts only the v2 form, `require` both ways, and relays; pki loading; firewall
  `ca_sha`; and the `nebula-cert` flows.

## Open items

- Classical key reuse: tell CA operators the classical CA key must sign nebula certificates only
  (C1). C2 is pinned by `TestCASigningInputsAreDisjoint`. See
  [Classical key reuse](#classical-key-reuse).
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
Field tested on real hosts on 2026-10-14 (`pq-lab/2026-10-14-hybrid/`, untracked): LAN median 3.2 ms
against 1.4 ms classical, +2.0 ms at 50 ms round trip, no fallbacks with `require` under loss.

The cryptographic review of 2026-10-14 found no break in the composition or the certificate
chain. Its outcomes are folded in above: deterministic ML-DSA signing, the fingerprint guidance,
the `skem` oracle note, the psk2 note (moot now that handshake is dropped), the pending-responder
exposure and the `sticky` default.

Accepted as is: a tunnel that came up classical between two v3 holders (say, the hybrid attempt
was dropped) stays classical until it rehandshakes for another reason. `require`, `sticky` and a
CA pool without v2 forms cover deployments that need more. PKCS#11 keys do not support v3.
