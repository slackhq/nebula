# Post-quantum handshakes

Status: prototype. A hybrid certificate is a version 2 certificate on a new curve,
`P384_MLKEM1024_MLDSA87`, whose algorithms are all in CNSA 1.0 or 2.0. A node on it makes
post-quantum handshakes, `ix_hybrid`, and nothing else, as a classical node makes classical ones:
curves never mix in a handshake, as P256 and Curve25519 do not today. The handshake messages are
far bigger than one packet and travel as fragments, see
[fragmented handshakes](fragmented-handshakes.md).

## Goals

1. **Confidentiality against harvest-now-decrypt-later.** Traffic recorded today must stay secret
   after a cryptographically relevant quantum computer exists, which needs a post-quantum key
   exchange now.
2. **Post-quantum authentication.** The CA's signature and the hosts' keys are post-quantum too,
   so a quantum attacker can neither forge a certificate nor impersonate a host.
3. **CNSA 2.0.** Every algorithm the curve chooses is one the NSA's Commercial National Security
   Algorithm Suite 2.0 allows, at the strength it asks for.
4. **Old nodes fail closed.** A node that does not know the curve can not verify a hybrid
   certificate, and treats it as it treats any certificate it can not verify.

Non-goals: identity hiding beyond what IX offers today, and signatures at handshake time. The only
signature in the system stays the CA's, inside the certificate.

## The hybrid curve

A certificate's curve already chooses its algorithms, and version 2 keeps the public key and the
signature opaque, so a new curve value needs no new certificate format. Version 1 certificates
can not carry it.

| Use | Algorithm | Standard | CNSA |
|---|---|---|---|
| Host key agreement | P-384 ECDH and ML-KEM-1024, side by side | FIPS 186-5, SP 800-56A; FIPS 203 | 1.0; 2.0 |
| CA signature | ML-DSA-87 and ECDSA P-384, composite | FIPS 204; FIPS 186-5 | 2.0; 1.0 |
| Noise hash, fingerprints | SHA-512 | FIPS 180-4 | 2.0 |
| Cookies | HMAC-SHA-512, for every curve | FIPS 198-1 | 2.0 |
| Transport cipher | `cipher`: AES-256-GCM, or ChaCha20-Poly1305 | SP 800-38D | 2.0 for AES only |

- **Host keys** pair P-384 with ML-KEM-1024 the way draft-ietf-tls-ecdhe-mlkem's
  `SecP384r1MLKEM1024` does: the public key is the uncompressed P-384 point (97 bytes) followed by
  the ML-KEM-1024 encapsulation key (1568 bytes). The private key is the P-384 scalar (48 bytes)
  followed by the ML-KEM-1024 seed (64 bytes).
- **CA keys** sign with `id-MLDSA87-ECDSA-P384-SHA512` of draft-ietf-lamps-pq-composite-sigs, with
  an empty context: the public key is the ML-DSA-87 key (2592 bytes) followed by the P-384 point
  (97 bytes), the signature the ML-DSA-87 signature (4627 bytes) followed by the DER ECDSA
  signature. Both sign `M' = "CompositeAlgorithmSignatures2025" || Label || 0 || SHA-512(M)`
  over the v2 signing input `M`, ML-DSA with the label as its context and ECDSA over
  `SHA-384(M')`, so neither half can be lifted into another protocol. Both halves must verify. The
  ECDSA half must also be low-s: nothing else covers it, and its high-s twin would give the
  certificate a second fingerprint. `cert.TBSCertificate.SignWith` normalizes what an external
  signer returns, since the composite signature allows either and the draft's own test vector is
  high-s. The private key is the ML-DSA-87 seed (32 bytes) followed by the raw P-384 scalar (48
  bytes), nebula's own form; the draft keeps the scalar in an RFC 5915 ECPrivateKey.
- **Fingerprints** of hybrid certificates are SHA-512, 128 hex characters, rather than SHA-256.
  A fingerprint is collision sensitive: the CA pool is keyed by it, a certificate names its issuer
  by it, and `ca_sha` firewall rules and `pki.blocklist` match on it. SHA-512 keeps that at the
  256 bits of the rest of the curve (NIST SP 800-57 Part 1 r5, Table 3), as FIPS 204 Appendix D.1
  grew ML-DSA's `mu` to 512 bits for category 5. `pki.blocklist` accepts both lengths.
- The composite signature is checked against the `id-MLDSA87-ECDSA-P384-SHA512` test vector of
  draft-ietf-lamps-pq-composite-sigs-19 in `cert/curve_hybrid_test.go`.

| PEM banner | Holds |
|---|---|
| `NEBULA P384 MLKEM1024 PUBLIC KEY`, `PRIVATE KEY` | host keys |
| `NEBULA MLDSA87 ECDSA P384 PUBLIC KEY`, `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` | CA keys |

Sizes: a host certificate is about 6.5 KB, a CA certificate about 7.5 KB.

## A node on the hybrid curve

A node's certificates share one curve, as they always have: `pki.cert` holds a version 2
certificate on the hybrid curve, `pki.key` its key, and `pki.ca` the hybrid CA that signed it.
There is no version 1 certificate on the curve, and no classical certificate beside it.

- **Handshakes follow the curve.** The node initiates `ix_hybrid` and answers only `ix_hybrid`; a
  classical node initiates and answers `ix_psk0`. A msg1 for the other curve is dropped before any
  work is done for it and logged at Info, rate limited, since it is most likely a node left on the
  wrong curve in a migration. An old node, which does not know the subtype, drops a hybrid msg1
  unlogged.
- **CAs.** A CA signs certificates on its own curve only. `pki.ca` may list classical and hybrid
  CAs together, and a build that can not run the curve, such as one under the FIPS 140-3 Go
  Cryptographic Module v1.0.0, which has no ML-DSA, leaves hybrid CAs out of the pool with a
  warning rather than failing, so one bundle serves every node.
- **Fingerprints** of hybrid certificates are 128 hex characters. `pki.blocklist` and firewall
  `ca_sha` rules take them as they take SHA-256 ones.
- Changing a node's curve on reload needs a restart, as changing between classical curves does.
- PKCS#11 keys are classical only.

`nebula-cert ca`, `keygen` and `sign` make hybrid CAs, keys and certificates with
`-curve P384-MLKEM1024-MLDSA87`. A hybrid CA signs version 2 certificates only.

## Handshake

`ix_hybrid` (subtype 3, on the wire always as its fragmented form 0x83) runs `HandshakeHybridIX` from
[github.com/DefinedNet/noise](https://github.com/DefinedNet/noise) (its `PQ_RESEARCH.md` gives the
design rationale and security argument), with P-384 for the DH tokens, ML-KEM-1024 for the KEM
tokens, SHA-512 as the hash and the operator's `cipher`: `Noise_IXhybrid_P384+MLKEM1024_AESGCM_SHA512`.

```
-> e, s
<- ekem, skem, e, ee, se, s, es
-> skem
```

- `e` and `s` carry composite keys, P-384 followed by ML-KEM-1024, the hybrid certificate's
  public key layout. DH tokens use the P-384 halves, `ekem` and `skem` encapsulate to the
  ML-KEM-1024 halves, and every secret goes into the one chaining key.
- **The responder's `e` is P-384 only.** It follows the responder's `ekem`, which already
  completed the ephemeral KEM exchange; a second one would be lost in the same cases as the first.
- The handshake form of the certificate leaves out its public key, as for any curve, since it
  travels in `s`.
- **KEM tokens first.** msg2 starts with `ekem, skem`, so the responder's static key and
  certificate are encrypted under keys that already include both KEM secrets. The initiator's
  certificate travels in msg1 in the clear, as in IX today.
- **Authentication.** The responder authenticates the initiator when msg3 decrypts, which depends
  on msg2's `skem` to the initiator's static key; the initiator authenticates the responder when
  the first packet under the new keys decrypts, which depends on msg3's `skem`. Knowing only a
  peer's P-384 private key gets an impersonator nowhere: as an initiator it can not read msg2, as
  a responder it can not read msg3.
- **Static ML-KEM keys and chosen ciphertexts.** msg2's `skem` ciphertext is encrypted under a key
  derived from the `ekem` secret, which whoever sent msg2 chose, so anyone who can address a
  pending initiator's index can have it decapsulate a ciphertext of their choosing. That is the
  IND-CCA setting ML-KEM is designed for, and `crypto/mlkem` is constant time. The responder
  decrypts msg3's `skem` ciphertext under the keys of a completed msg2 before decapsulating, so it
  only ever decapsulates ciphertexts the genuine initiator sealed.
- Hybrid certificates go with this subtype and nothing else: one on another subtype, or a classical
  certificate on this one, is a protocol error.

Message sizes, without the 16 byte header, and the data fragments each takes (1160 bytes each):

| Message | Minimal certificate | Typical certificate |
|---|---|---|
| msg1 | 8187 B, k=8 | 8259 B, k=8 |
| msg2 | 9805 B, k=9 | 9876 B, k=9 |
| msg3 | 1600 B, k=2 | 1600 B, k=2 |

The minimal certificate has a 9 byte name, no groups and one IPv4 network; the typical one a 35
byte name, three groups (`prod`, `web`, `ssh-admins`) and an IPv4 and an IPv6 network.

Hybrid handshakes always travel as fragments: `handshakes.fragment: never` applies to classical
handshakes only.

### Three messages in the manager

- **Responder.** After msg2 the responder keeps the handshake pending under its local index. A
  repeat of that msg1, from an initiator still waiting for msg2, gets msg2 resent with fresh
  symbols on the path the repeat came by, and starts no second handshake; so does a repeat that
  arrives after the tunnel is up, as a classical repeat does. msg3's fragments name the responder's index, so they reach the pending entry and never
  the pre-authentication table; its reassembly is capped at 4 KiB. Until msg3 verifies, data for
  that index is dropped quietly: a RecvError would tear down the initiator's new tunnel. On
  completing, the responder sends an empty `Test`/`TestReply` under the new keys so the initiator
  hears back without traffic. A pending responder expires after the handshake timeout.
- **Initiator.** Writing msg3 yields the transport keys, so the tunnel goes live at once, readable
  only by the real responder; msg3 goes out before any packets cached during the handshake. Until
  anything from the responder decrypts on the new tunnel, msg3 is resent with fresh symbols on a
  linear backoff, and if nothing has decrypted by the handshake timeout the tunnel is closed.
- **Lost confirmation.** A msg3 fragment for a hybrid tunnel the responder already completed means
  the initiator is still waiting, so the responder confirms again, at most once per retry interval
  and only to the tunnel's own remote, never to the fragment's source.
- **Crossing handshakes.** When both nodes initiate at once, each answers the other's msg1 as a
  responder. msg3 settles it: the initiator only sends msg3 once it has committed to its tunnel,
  so a responder takes the tunnel msg3 completes even over a newer one, rather than refusing it as
  too old and leaving the initiator with a tunnel no one holds.

### Pending hybrid responders

A hybrid responder that answered msg1 keeps a pending entry until msg3 arrives or the handshake
timeout passes. msg1 is cleartext and nothing covers `e` or `Time`, so from one captured msg1 an
attacker can mint distinct valid msg1s, each costing the responder the whole msg1 and a pending
entry. Accepted as is: the work is the same class as classical IX's pre-authentication cost, the
expiry bounds the state in time and the fragment table bounds the bytes in flight. If it needs
tightening, cap pending responders per certificate fingerprint and in total, and count them toward
the cookie threshold.

## Migrating a network

There is no setting to turn post-quantum handshakes on: a node on the hybrid curve makes them, and
classical and hybrid nodes can not reach each other. A network moves to the curve as a whole:

1. Make a hybrid CA with `nebula-cert ca -curve P384-MLKEM1024-MLDSA87` and add it to every node's
   `pki.ca`, beside the classical CA. Nodes whose build can not run the curve leave it out.
2. Reissue each node on the hybrid curve and restart it. A node can only reach peers on its own
   curve, so move lighthouses and relays with the nodes they serve, or run the hybrid nodes as a
   second overlay, with their own lighthouses, until the last classical node is gone.
3. Drop the classical CA from `pki.ca`.

## CNSA 2.0

The curve was chosen against the NSA's "CNSA 2.0 and Quantum Computing FAQ", version 2.2 of
October 2026. What it asks for, and where nebula stands:

- **ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384 or SHA-512** for every classification level, and
  SHA-256 nowhere, not even in a KDF. The hybrid curve uses ML-KEM-1024, ML-DSA-87 and SHA-512
  throughout its handshake, keys and fingerprints. `cipher: aes` is AES-256-GCM; `chachapoly` is
  not a CNSA algorithm.
- **Hybrids are not required.** P-384 rides along with ML-KEM-1024 and ML-DSA-87 so the curve is
  no weaker than CNSA 1.0 against classical attacks should a post-quantum algorithm fall.
- **"NSS systems using PKI should not use novel mechanisms to support multiple algorithms within a
  single certificate".** A composite signature is such a mechanism. The curve uses one anyway,
  so a hybrid CA has a single key and every hybrid certificate a single signature; dropping the
  ECDSA half would make the CA pure ML-DSA-87 at the cost of the classical fallback.
- **HashML-DSA is not allowed.** The composite signature uses pure ML-DSA-87 over `M'`.
- Compliance needs an NSA-approved manner of implementation, such as a NIAP protection profile;
  this prototype makes no such claim.

## Open items

- Publish DefinedNet/noise and drop the `replace` in `go.mod`. The P-384 only responder `e` is on
  the local clone's `drop-responder-ekem-key` branch (b4a892b), not yet in DefinedNet/noise.
- DefinedNet/noise `ReadMessage` returns `ErrShortMessage` without rolling back the symmetric
  state ([DefinedNet/noise#2](https://github.com/DefinedNet/noise/issues/2)): one spoofed short
  packet to a pending initiator's index kills that attempt until it times out. Blocks publishing
  the module.
- Field test against the version 3 certificate design (#1974).
