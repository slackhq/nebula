# Fragmented handshakes

A handshake message carries the sender's certificate, and a certificate with many groups, names
or networks can outgrow one packet. Until now such a message went out as one oversized UDP
datagram and relied on IP fragmentation, which too many paths drop: firewalls that discard
fragments, NATs that cannot map them, and IPv6 paths where only the sender may fragment. The
handshake then failed with nothing in the logs but a timeout.

A fragmented handshake sends the message as Reed-Solomon coded symbols instead, each in a packet
small enough for the IPv6 minimum MTU even when relayed. The handshake itself does not change:
the receiver reassembles the message and hands the handshake `Machine` exactly the packet it
would have received unfragmented. The transport was built for post-quantum handshakes, whose
messages are always several packets long, and works the same for classical ones.

## When a message is fragmented

`handshakes.fragment` says when a node sends its own handshake messages as fragments:

- `auto` (the default): a message too big for one packet (over 1200 bytes) goes as fragments,
  and so does a response to a msg1 that came as fragments, since its sender can reassemble them.
  Every other message goes as one packet, as before, so today's certificates see no change.
- `always`: every handshake message goes as fragments.
- `never`: every message goes as one packet however big, as before this change.

A node reassembles fragments from others whatever the setting. `handshakes.repair_delay` (10ms)
is how long repair fragments trail the data fragments; both settings reload.

A peer running an older nebula can not reassemble fragments. A message too big for one packet
goes to it as fragments anyway: the oversized datagram it could have read depended on IP
fragmentation, which is what fails, so nothing that worked reliably is lost. Such a handshake
times out as it may have before; `never` on either side keeps the old behaviour where it was
working.

## Wire format

A fragment is marked by `header.HandshakeFragmented` (0x80) on the handshake subtype, and the
rest of the subtype still names the handshake pattern: a fragment of a classical IX message has
subtype `ix_psk0 | 0x80`, shown as `ix_psk0_fragmented`. Every packet of a fragmented message is:

```
Nebula header (16)   Version | Type=Handshake | Subtype|0x80 | Reserved=0 | RemoteIndex | Counter
Fragment header (8)  FragID u32 | MsgLen u16 | Index u8 | Flags u8
Cookie (16)          only when Flags has 0x01
Symbol               SymbolSize bytes
```

- `Counter` is the handshake message number (1, 2). `RemoteIndex` is 0 for msg1, as for an
  unfragmented msg1.
- `FragID` is the sender's local index (random, non-zero).
- `MsgLen` is the length of the whole message, at most 65535 bytes. Both ends derive the layout
  from it: `K = ceil(MsgLen / 1160)`, `SymbolSize = ceil(MsgLen / K)`. Every symbol has the same
  size. Room for a cookie is always reserved, so a packet is at most 16 + 8 + 16 + 1160 = 1200
  bytes with or without one, and 1232 relayed (a 16 byte header and a 16 byte tag), the IPv6
  minimum MTU budget also used by DNS Flag Day 2020.
- `Index < K` is a data symbol (a slice of the message, the last one zero padded);
  `Index >= K` is a repair symbol.
- `Flags` bit 0x01 means a cookie follows the fragment header. Other bits must be zero.

A cookie reply is a bare 32 byte packet:

```
Nebula header (16)   Version | Type=Handshake | Subtype|0x80 | Reserved=0 | RemoteIndex=FragID | Counter=0
Cookie (16)
```

It names the initiator by its index, as its FragID does, so the initiator finds its handshake the
same way it finds msg2.

## Forward error correction

Messages are protected with a systematic Reed-Solomon code over GF(2^8), implemented in
`handshake/fec`:

- The repair rows form a Cauchy matrix, `coefficient(row, col) = 1 / (row XOR col)` with
  `row >= K > col`, so every square submatrix is invertible and **any K distinct symbols
  reconstruct the message**. Naive identity-over-Vandermonde constructions are not MDS (the PAR1
  flaw and the 1997 Plank tutorial erratum).
- A repair row depends only on its index, so repair symbols are generated on demand and their
  indexes never need to be agreed in advance. Up to 256 symbols exist per message.
- Known-answer vectors in `fec_test.go` pin the encoding and were cross-checked against an
  independent implementation; changing them is a wire format change.

**The sender chooses m**, the number of repair symbols per attempt, `m = max(2, ceil(K/3))`. The
receiver only needs any K symbols, so this is policy and can change without a protocol change.

**Retries send fresh symbols.** Attempt 0 sends indexes `0 .. K+m-1`; each retry sends the next
`K+m` unused indexes. The receiver merges all distinct symbols across attempts, so no received
fragment is wasted. Indexes are a deterministic function of the message, so retransmits stay
idempotent: the responder caches msg2 itself and regenerates any symbol.

**Repair symbols trail the data.** Data symbols go out back to back; repair symbols follow after
`repair_delay`, so a queue tail drop at the end of the data run does not also take the repair.

## Receiver rules

Implemented in `handshake/fragment` (`Sender`, `Assembly`, and the capped `Table`).

- Fragments are stored individually as they arrive and charged against a memory cap. Nothing is
  allocated from a claimed size alone (FragmentSmack, game-engine "fragment bombs").
- `MsgLen` must be identical for every fragment of a `FragID`; a mismatch drops the whole entry.
- The decoder keeps at most K distinct symbols, so an entry never exceeds about MsgLen bytes
  however many repair symbols arrive.
- When K symbols are present the message is decoded and handed to the handshake `Machine` as a
  synthetic `[header | message]`, with the fragmented flag cleared. The Machine never sees
  fragments.
- A completed msg1 the responder answered is remembered without its symbols, outside the memory
  and per-source caps, for the idle timeout: which symbol indexes it has seen, and its hash.
  Fragments still trailing the attempt that completed it are counted and dropped. Once as many
  new symbols as it has data symbols arrive, which only a retry offers, it is reported as a
  repeat and the cached response is resent, as long as the tunnel it answered still exists.
  Without this, the repair fragments trailing a msg1 whose data fragments already completed it
  open an entry that can never complete, and back to back handshakes from one source run into
  its quota.
- If the handshake rejects a decoded message, the entry is discarded and the next attempt
  supplies fresh symbols.
- msg1 entries, from senders not yet authenticated, live in a table keyed by (source address or
  relay index, FragID) with a total memory cap of 4 MiB and 1024 entries, per-source quotas of 4
  (/32 for IPv4, /64 for IPv6, one relay channel), a sliding TTL of 3 s refreshed by progress,
  and random eviction under pressure.
- msg2 reassembly attaches to the pending handshake found by RemoteIndex, in two slots keyed by
  the responder's FragID. When a stale lighthouse address for the peer belongs to another host
  now, both hosts answer the same msg1, and their interleaved bursts would wipe each other out
  of a single slot that emptied on every FragID change; with a slot each, whichever completes
  first is processed, and a wrong host's answer takes the usual block-and-retry path.

## Retransmission and amplification

- Only timers cause transmission, with one reactive exception: the responder resends its cached
  msg2 when a copy of msg1 completes again. An initiator sends msg1 to every address it knows and
  through its relays, the responder reassembles each path separately, and each path's first
  completion is answered on that path at once. A path that only works one way is then covered by
  the others in the same attempt. After that a path is answered again at most once per retry
  interval, and only once K symbols not seen before on it arrive.
- Duplicate msg1 detection compares the decoded message to the cached one **before** running
  Noise or certificate verification.
- Before an address is validated, a responder sends at most 3x the bytes it received from it as
  fragments (QUIC's rule). Normal handshakes sit near 1x. A response that would need more, a
  responder whose certificate is several times the initiator's, is held back: the responder
  answers with a cookie reply instead, the initiator resends msg1 as fragments carrying the
  cookie, which proves its address, and the remembered msg1 is answered in full without redoing
  the handshake. The cookie reply is the same one a responder under load sends.
- A response that fits one packet goes as one, as before, with no budget beyond that.

## Denial of service

The responder can no longer complete statelessly on msg1, since msg1 arrives in pieces. Defenses
are the capped table above plus a **cookie under load**, in the style of WireGuard's mac2, QUIC
Retry and the SCTP state cookie:

- Once the msg1 table is at least half full (by bytes or by entries), every msg1 fragment must
  carry a valid cookie. One without is answered with a cookie reply and leaves no state.
  Fragments that already belong to an entry need one too, so an attacker can not hold old entries
  open.
- A cookie is `HMAC-SHA-512(secret, source address and port, relay channel, FragID)` truncated to
  16 bytes. The secret rotates every 2 minutes and the previous one is still accepted, so a
  cookie is good for 2 to 4 minutes.
- Replies are never larger than the packet that prompted them (no amplification) and are rate
  limited as a whole (a burst of 256, then 1000 per second), so spoofed floods can not turn the
  responder into a reflector.
- The initiator attaches the cookie to its msg1, switching it to fragments if it was going as one
  packet, since only a fragment carries a cookie, so every later packet carries it, and
  immediately resends fresh symbols to the address the reply came from, at most once per retry
  interval.
- An attacker on the path can forge a cookie reply; the bogus cookie is simply rejected and
  answered with a real one.

### Injected symbols

The decoder keeps the first K distinct symbols it sees, so one forged symbol in those K spoils
that attempt's decode; the handshake rejects the result and the next attempt brings fresh symbols.
Forging one needs the attempt's FragID or index, which are random 32 bit values, and for msg1 the
initiator's exact address and port too, so in practice only an attacker who sees the traffic can
do it. An attacker who can also drop packets gains nothing new. One who can only inject, and races
a forged symbol into every attempt, can stop a fragmented handshake where it could not stop an
unfragmented one; symbols can not be authenticated before a key exists, and keeping spare symbols
to find a consistent subset only raises the number of forgeries needed. `never` avoids fragments
where that matters more than IP fragmentation does.
