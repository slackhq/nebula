# Operator guide: running rosenpass as a sidecar for nebula PQ

This guide walks an operator through pairing the default nebula binary
with an external [rosenpass](https://rosenpass.eu) daemon to obtain
post-quantum (PQ) PSK material for the Noise handshake. It covers two
deployment paths (sidecar default, embedded behind a build tag), a
copy-pasteable systemd unit, a copy-pasteable `rosenpass.toml`, the
cert-v2 `rosenpassPubKeySha256` extension and the `nebula-cert sign`
flags that set it (`-rp-pubkey-from`, `-rp-pubkey-sha256`), the
`pq.rp_binding.mode` tri-state knob, the lighthouse-gossip-driven
live-upgrade path, and the policy modes the runtime exposes.

Nebula adds PQ via PSK-mixing: the handshake stays X25519/Ed25519 for
authentication and key agreement, and a separately negotiated 32-byte
PSK is mixed into the Noise key schedule. That gives
harvest-now-decrypt-later (HNDL) resistance for recorded ciphertext.
Active impersonation by an attacker with a cryptographically relevant
quantum computer (CRQC) is **not** mitigated by this construction;
rotate to PQ signatures when a standardised, performant primitive
lands.

### Audit posture (read this before deploying)

- The **rosenpass protocol and the Rust reference implementation**
  were audited by Cure53 (commissioned via NLnet). The sidecar
  deployment path uses that implementation unmodified.
- The **`cunicu.li/go-rosenpass` Go port** linked by the embedded
  build has **not** been audited. The embedded build is gated behind
  the `rosenpass_embedded` build tag for that reason and is intended
  for labs, CI, and convenience deployments, not production with
  strong audit requirements.
- The nebula-side PSK plumbing (`pq` and `pq/rposvc` packages, cert
  extension handling, `pq.rp_binding` validation) has gone through
  internal security review but no external audit.


## 1. The two PQ deployment paths

| | Sidecar (default build) | Embedded (build-tag opt-in) |
| --- | --- | --- |
| Build command | `go build ./cmd/nebula` | `go build -tags rosenpass_embedded ./cmd/nebula` |
| Rosenpass implementation | Rust reference daemon from rosenpass.eu, in its own systemd unit | `cunicu.li/go-rosenpass` linked into the nebula binary |
| Audit status of the rosenpass code path | Rosenpass protocol and Rust reference implementation have been audited by Cure53 (commissioned via NLnet) | go-rosenpass has **not** been audited (see upstream README); only the protocol audit applies |
| PSK plumbing | `rosenpass --key-out <dir>` writes 32-byte files into a directory that nebula's `pki.pq_psk_dir` watches via `fsnotify` | In-process `MemoryProvider`, no files on disk |
| Peer pubkey distribution | Operator provisioning (Ansible/scp/IaC) — out-of-band | Lazy discovery over the nebula tunnel after a first IXPSK0 handshake |
| Extra process to supervise | Yes | No |

The default build (sidecar path) is what this repository ships and is
what production deployments should prefer when audit posture matters.
The embedded path remains available for lab / convenience deployments
and for CI matrices, but requires an explicit `-tags
rosenpass_embedded` rebuild.

If `pq.embedded_rosenpass.enabled: true` is set on a default-build
binary, nebula logs a warning at startup and continues — PSKs still
flow through `pki.pq_psk_dir` if configured.


## 2. Sidecar setup walkthrough

### 2.1 Install the Rust rosenpass daemon

Follow the upstream instructions at <https://rosenpass.eu>. Distribution
packages exist for some platforms; otherwise build from the
[rosenpass/rosenpass](https://github.com/rosenpass/rosenpass) repository
and place the resulting `rosenpass` binary on `$PATH` (typically
`/usr/local/bin/rosenpass`). Verify with:

```sh
rosenpass --version
```

### 2.2 Generate a keypair per node

On each nebula node:

```sh
sudo install -d -m 0700 -o rosenpass -g rosenpass /etc/rosenpass
sudo -u rosenpass rosenpass gen-keys \
    --public-key /etc/rosenpass/rp.pub \
    --secret-key /etc/rosenpass/rp.sk
```

The public key is non-sensitive and gets distributed to peers. The
secret key never leaves the host.

### 2.3 Bind the public key to the nebula cert (cert-v2)

The node's nebula v2 certificate carries a CA-signed `rosenpassPubKeySha256`
extension that pins which rosenpass keypair is allowed to derive PSKs for
this identity. The extension is the sole trust binding for the rosenpass
identity (see section 3).

Two equivalent ways to set it:

**Recommended: point at the public key file directly.** Copy each node's
`rp.pub` to the CA host (it is non-secret), then:

```sh
nebula-cert sign \
    -ca-crt ca.crt -ca-key ca.key \
    -name node-a -networks 192.168.100.10/24 \
    -version 2 \
    -rp-pubkey-from /path/to/rp.pub
```

`nebula-cert` reads the file, computes SHA-256 and stores the digest in
the cert. Works against the rosenpass binary's output (`rosenpass
gen-keys`) and against the file the embedded build writes at its
configured `state_dir/rp.pub` — both are the same 524-byte McEliece
public key format.

**Alternative: pre-compute the hash.** Useful when you have a hash from
another tool, or when scripting against a non-file source (e.g. an
inventory variable):

```sh
RP_PUB_SHA256=$(sha256sum /etc/rosenpass/rp.pub | awk '{print $1}')

nebula-cert sign \
    -ca-crt ca.crt -ca-key ca.key \
    -name node-a -networks 192.168.100.10/24 \
    -version 2 \
    -rp-pubkey-sha256 "${RP_PUB_SHA256}"
```

The two flags are mutually exclusive — `nebula-cert sign` errors if both
are supplied. Either path requires a v2 certificate; v1 certs have no
extension area.

### 2.4 Distribute peer public keys

Ship each peer's `rp.pub` to every other peer via your existing
provisioning channel (Ansible, scp during host bootstrap, an artifact
repository, etc). Place them under a directory like
`/etc/rosenpass/peers/<peer-name>.pub`. The bytes are not secret, but
must be authentic — that's what the cert extension above enforces at
nebula's side; rosenpass itself trusts whatever it reads from disk.

### 2.5 Write `/etc/rosenpass/rosenpass.toml`

Below is a minimal config for a node with two peers. Adjust the listen
address to the nebula tun IP so that rosenpass traffic travels inside
the nebula tunnel (recommended — handshakes inherit nebula's network
reachability and any nebula firewall rules).

```toml
# /etc/rosenpass/rosenpass.toml
public_key = "/etc/rosenpass/rp.pub"
secret_key = "/etc/rosenpass/rp.sk"

# Listen on this node's nebula IP, inside the tunnel.
listen = ["192.168.100.10:51821"]

# Optional verbose logging.
verbosity = "Verbose"

[[peers]]
public_key = "/etc/rosenpass/peers/node-b.pub"
endpoint   = "192.168.100.11:51821"
# key_out is the per-peer PSK destination. The filename MUST be the
# lowercase SHA-256 hex of *this peer's nebula static pubkey* + ".psk".
# Compute it once at provisioning time and bake into config.
key_out    = "/var/lib/nebula/pq_psk/<sha256-hex-of-node-b-nebula-pubkey>.psk"

[[peers]]
public_key = "/etc/rosenpass/peers/node-c.pub"
endpoint   = "192.168.100.12:51821"
key_out    = "/var/lib/nebula/pq_psk/<sha256-hex-of-node-c-nebula-pubkey>.psk"
```

Notes:

- The `<sha256-hex>.psk` filename convention is what nebula's
  `FileProvider` looks up: when nebula initiates a handshake to a peer
  with static pubkey `P`, it computes `sha256(P)` in lowercase hex and
  reads `<pq_psk_dir>/<hex>.psk` (must be exactly 32 bytes). Rosenpass
  does not know about this convention — it just writes wherever
  `key_out` points — so the operator is responsible for computing the
  hash. Extract the peer's static pubkey from its nebula cert with
  `nebula-cert print` and pipe it through `sha256sum`.
- Rosenpass writes PSKs atomically via tempfile + rename, which is what
  `FileProvider`'s 250ms debounce expects.
- Rotation interval is set by rosenpass (defaults are sensible). On
  each rotation nebula's fsnotify watcher picks the new PSK up and
  triggers an immediate rekey for affected peers without SIGHUP.

### 2.6 systemd unit

```ini
# /etc/systemd/system/rosenpass.service
[Unit]
Description=Rosenpass PQ key-exchange daemon (nebula sidecar)
Documentation=https://rosenpass.eu
After=network-online.target nebula.service
Wants=network-online.target
# Rosenpass listens on the nebula tun IP; the tunnel must exist first.
Requires=nebula.service

[Service]
Type=simple
User=rosenpass
Group=rosenpass
# Make the PSK directory writable for rosenpass and readable for nebula.
# Both daemons share the "nebula-psk" supplementary group in this example.
SupplementaryGroups=nebula-psk
ExecStartPre=/usr/bin/install -d -m 2770 -o rosenpass -g nebula-psk /var/lib/nebula/pq_psk
ExecStart=/usr/local/bin/rosenpass exchange-config /etc/rosenpass/rosenpass.toml
Restart=on-failure
RestartSec=5s

# Hardening.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=/var/lib/nebula/pq_psk /etc/rosenpass

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rosenpass.service
journalctl -u rosenpass -f
```

### 2.7 Configure nebula to consume the PSK directory

In `/etc/nebula/config.yml`:

```yaml
pki:
  ca:   /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key:  /etc/nebula/host.key
  pq_psk_dir: /var/lib/nebula/pq_psk
  # Staleness watchdog: warn (+ pq.file.snapshot_stale counter) if the
  # PSK directory stops changing for this long while PSKs are loaded.
  # The files of a dead sidecar keep serving valid (stale) material
  # silently otherwise — systemd restarts cover crashes, but not a
  # daemon that is up yet failing its peer key exchanges. 3-5x the
  # rekey interval is a good value (rosenpass rekeys ~every 2 min).
  pq_psk_stale_warn: 10m

pq:
  mode: opportunistic
  # state_path persists the boot-path identity cache so group policy
  # overrides apply on cold start without waiting for a fresh handshake.
  state_path: /var/lib/nebula/pq-state.json
```

For dashboards, prefer the `pq.file.snapshot_age_seconds` gauge
(exported regardless of `pq_psk_stale_warn`): healthy rotation
saw-tooths around the rekey interval, a climbing line is a dead or
wedged sidecar.

Reload nebula (HUP is fine — `pq_psk_dir` is HUPable; the watcher is
re-attached against the new config). PSKs already on disk are honoured
immediately.

### 2.8 Permissions checklist

- `/etc/rosenpass/rp.sk`: `0600`, owned by `rosenpass`. Never readable
  by the nebula user.
- `/etc/rosenpass/rp.pub`, `/etc/rosenpass/peers/*.pub`: world-readable
  is fine (the bytes are public).
- `/var/lib/nebula/pq_psk/`: `2770`, owned by `rosenpass:nebula-psk`.
  Setgid so files inherit the group. Add both users to `nebula-psk`.
- `/var/lib/nebula/pq_psk/*.psk`: `0640` is enough; nebula only reads.
  Rosenpass writes via tempfile + rename, so the destination perms
  should be tightened by umask (`umask 0027` in the unit, or rely on
  the daemon's default which is `0600` per its docs).

Nebula's `FileProvider` opens PSK files with `O_NOFOLLOW` and skips
non-regular files, so symlinks pointing outside the directory will be
rejected.


## 3. Cert-v2 `rosenpassPubKeySha256` extension

The CA-signed cert v2 `rosenpassPubKeySha256` extension carries the
SHA-256 of the holder's rosenpass public key. This is the **sole**
trust binding between a nebula identity and its rosenpass identity.
Older TOFU pinning has been removed.

- Sign-time: pass `-rp-pubkey-from <path>` (recommended) or
  `-pq-psk-binding <hex>` (canonical; `-rp-pubkey-sha256 <hex>` is the
  deprecated alias) to `nebula-cert sign` (see section 2.3). The
  resulting cert must be v2.
- `nebula-cert print -json` emits this value under **both** the
  canonical `pqPskBinding` key and the legacy `rosenpassPubKeySha256`
  key (same hex), so existing parsers keep working.
- Verify-time: when nebula learns a peer's rosenpass pubkey (in the
  embedded path: from the in-tunnel discovery service; in the sidecar
  path: optionally from a `.rpinfo` companion file — see section 3a),
  it cross-checks against the hash in the peer's cert. Cert is
  authoritative: any other source that disagrees with the cert is
  ignored under `pq.rp_binding.mode=enforce`.

Peers whose certs **lack** the extension are still accepted; they
fall through to IXPSK0 (mesh PSK) or to non-PQ handshakes depending
on `pki.pq_psk_path` / `pq.mode`. Issue them new v2 certs with the
extension during the next cert rotation.


## 3a. `.rpinfo` companion files and `pq.rp_binding.mode`

The cert extension by itself proves that, at signing time, the CA was
willing to vouch for "this nebula identity owns rosenpass pubkey with
SHA-256 = X". To catch the case where the sidecar has been re-keyed (or
swapped, or compromised) since the cert was signed, nebula can also be
told what hash it should expect to see for the PSK currently on disk.
That second piece of evidence lives in a `<peer-hash>.rpinfo` companion
file alongside each `<peer-hash>.psk` in `pki.pq_psk_dir`.

### File format

For each peer the sidecar derives a PSK for, drop a file at
`<pq_psk_dir>/<peer-sha256-hex>.rpinfo` (the same stem as the matching
`.psk`) containing exactly 64 lowercase hex characters — the SHA-256 of
the peer's rosenpass public key — optionally followed by a newline.
Anything else (wrong length, uppercase, non-hex, oversize, symlink) is
logged as malformed and skipped without preventing the PSK from
loading. Absent `.rpinfo` is normal; nebula records "no binding info"
for that peer.

```sh
# Compute the rpinfo for peer-B and drop it next to the PSK file.
# peer-B-nebula-hash is sha256(peer-B's nebula static pubkey) in
# lowercase hex — see section 2.5 for how to obtain it.
sha256sum /etc/rosenpass/peers/peer-B.pub \
  | awk '{print $1}' \
  > /var/lib/nebula/pq_psk/<peer-B-nebula-hash>.rpinfo
```

### `pq.psk_binding.mode` (canonical; `pq.rp_binding.mode` is a deprecated alias)

The canonical config key is **`pq.psk_binding.mode`**. The historical
key `pq.rp_binding.mode` is still accepted as a deprecated alias and
behaves identically; new deployments should prefer `pq.psk_binding.mode`.
Throughout this doc, read `pq.rp_binding.mode` as `pq.psk_binding.mode`.

At PSK-use time (both initiator and responder) nebula cross-references
the peer's cert extension against the local `.rpinfo`. The
`pq.psk_binding.mode` knob controls what happens when those two pieces
of evidence disagree (or one is missing):

| Mode | Cert ext present, `.rpinfo` missing | Cert ext present, `.rpinfo` mismatches | Cert ext absent, `.rpinfo` present | Both match / both absent |
| --- | --- | --- | --- | --- |
| `off` | use PSK silently | use PSK silently | use PSK silently | use PSK silently |
| `warn` (default) | use PSK, Warn log | use PSK, Warn log | use PSK, Info log | use PSK silently |
| `enforce` | **refuse PSK**, Error log | **refuse PSK**, Error log | use PSK, Info log | use PSK silently |

A refused PSK is treated as if the Provider had returned nil: the
handshake falls back to IXPSK0, or to plain Noise, or fails entirely
depending on `pq.mode`. Logs at the refused paths carry both `certHash`
and `rpinfoHash` so the operator can immediately see which side was
believed.

When to pick which:

- `off` — pre-Gap-1 behaviour. Useful during major version skew between
  operators if you want maximum lenience, or for setups where nebula
  isn't responsible for rosenpass posture at all.
- `warn` (default) — see exactly what's happening in logs without
  breaking any tunnel. The right setting for the migration window
  while you roll out new certs and provisioning script changes.
- `enforce` — production posture once `.rpinfo` files and the cert
  extension are deployed everywhere. A re-keyed sidecar then fails the
  handshake instead of silently downgrading.

### Migration playbook

The default `warn` mode is fully backwards compatible: an operator
running today with no `.rpinfo` files and certs that don't carry the
extension sees zero behaviour change. Migrate at your own pace:

1. Stay on `warn` (the default; nothing to set).
2. Roll out new v2 certs with the `-rp-pubkey-sha256` extension via the
   CA — same workflow as section 2.3, just for every existing host.
3. Update the sidecar provisioning script to emit a
   `<peer-hash>.rpinfo` file alongside each `<peer-hash>.psk`
   `key_out`. Atomic write (tempfile + rename), same convention as the
   PSK file itself. Re-emit on every key rotation in case the peer's
   rosenpass pubkey changed.
4. Watch the nebula logs for `pq: peer cert claims rosenpass binding
   but no rpinfo present` or `pq: rosenpass binding mismatch`. Each
   line names the peer and both hash values; investigate any
   surprises.
5. Once the warnings are clean across the fleet, set
   `pq.rp_binding.mode: enforce` in `config.yml` and HUP nebula. The
   knob is hot-reloadable, no restart needed.

The validation also runs in the embedded build (`-tags
rosenpass_embedded`), but the `.rpinfo` companion files are unique to
the sidecar build's `FileProvider`. The in-process `MemoryProvider` has
no equivalent on-disk source today; the embedded path only consults
the cert extension (plus the lighthouse-gossip path documented next).


## 3b. Lighthouse-gossip live upgrade (embedded path)

For the embedded build, `HostUpdateNotification` carries two optional
fields — `RosenpassPubkeySha256` and `RosenpassPort` (plus the TCP
`DiscoveryPort`) — so peers learn each other's rosenpass identities
over the existing lighthouse channel without operator
pre-distribution. The fields are non-breaking: old peers omit them
and ignore them.

The trust model is unchanged: **the CA-signed cert extension is
authoritative**. Gossip is a routing convenience (where to fetch the
peer's public key from, what UDP port to talk to) plus a secondary
identity claim that is only consulted for binding decisions when it
agrees with the cert. Under `pq.rp_binding.mode=enforce`, a gossiped
hash that disagrees with the CA-signed cert is a hard refuse, just
like an `.rpinfo` disagreement (see `pq/rp_binding.go`).

Gossiped port changes also trigger re-registration: if a peer
gossips a new `RosenpassPort` after we've already added them to the
local rosenpass coordinator, the coordinator drops the old entry
and re-adds the peer at the corrected endpoint. The re-registration
loop is bounded — `pendingReplayCap` (10) caps how many times a
single in-flight fetch will be replayed before the goroutine bails
and waits for the next Notify — so a peer whose gossip churns
rapidly cannot pin a fetch goroutine indefinitely.

Operators on the sidecar build can ignore this section entirely;
peer endpoints come from `rosenpass.toml`. The corresponding config
keys for the embedded build are the canonical `pq.provider_port` (UDP)
and `pq.discovery_port` (TCP). The legacy keys `pq.rosenpass_port` /
`pq.embedded_rosenpass.port` (UDP) and `pq.embedded_rosenpass.discovery_port`
(TCP) are still accepted as deprecated aliases / fallbacks.


## 4. Policy modes recap

Configured under `pq:` in `config.yml`. The handshake mechanism
(IXPSK0 vs IXPSK2) is the same in all modes; what differs is when
downgrade is tolerated.

- `opportunistic` (default): use IXPSK2 if a PSK for the destination
  peer is present in the provider; otherwise fall back to IXPSK0 (mesh
  PSK from `pq_psk_path`, if any) or to plain Noise (no PQ). Suitable
  for bootstrap and gradual rollout.
- `required`: refuse to complete a handshake with any peer for which
  PSK material is configured but unresolvable. Switch the mesh to this
  once PSK distribution is complete.
- `disabled` / `off`: only valid inside `pq.group_overrides`, not as
  the top-level `pq.mode`. Skips PQ entirely for matching peers.
  Useful while migrating legacy / upstream-vanilla peers.

Per-group overrides via cert-asserted (CA-signed) `groups`:

```yaml
pq:
  mode: opportunistic
  group_overrides:
    lighthouses: required
    legacy:      disabled
  group_order:
    - lighthouses
    - admins
    - legacy
```

`group_order` is first-match-wins when a peer is in multiple
overridden groups. Without it, the matcher walks groups alphabetically
(deterministic but rarely what you want).


## 5. Building from source

```sh
# Default build — sidecar mode. Does not pull cunicu.li/go-rosenpass.
go build ./cmd/nebula

# Embedded build — links go-rosenpass into the binary and exposes
# pq.embedded_rosenpass.* config keys.
go build -tags rosenpass_embedded ./cmd/nebula
```

The build tag is also wired through tests in `pq/rposvc/` (the
sub-package is fully gated). CI matrices should build and test both
configurations:

```sh
go test ./...
go test -tags rosenpass_embedded ./...
```

### 5.1 Listener bind address overrides

By default both embedded listeners bind to the cert's primary nebula
tun IP so all Rosenpass traffic rides inside the encrypted overlay.
Two config keys override this:

- `pq.embedded_rosenpass.listen_host` — UDP listener bind address
- `pq.embedded_rosenpass.discovery_listen_host` — TCP discovery bind
  address (defaults to `listen_host` when unset)

Use these for smoke tests, lab deployments, or any node running with
`tun.disabled: true`. Nebula refuses to start with
`tun.disabled: true` + `embedded_rosenpass.enabled: true` unless
`listen_host` is set, since the default bind target (the tun IP) is
never assignable without the tun. Example smoke config snippet:

```yaml
tun:
  disabled: true
pq:
  embedded_rosenpass:
    enabled: true
    listen_host: "127.0.0.1"
    discovery_listen_host: "127.0.0.1"
```


## 6. Migration from earlier deployments

### 6.1 From `pq.mode: tofu`

Earlier development builds exposed a TOFU mode that pinned a peer's
rosenpass public key on first sight. Both the mode and the per-peer
TOFU pin in `pq.Store` have been removed; the cert-v2 extension is
the sole trust binding. Two consequences for operators upgrading
from a build that used TOFU:

1. `pq.mode: tofu` is no longer accepted; the config schema rejects
   it at parse time with a remediation hint. Use `opportunistic`
   (or `required` if every peer has PSK material).
2. Peers presenting v1 certs (or v2 certs without the
   `rosenpassPubKeySha256` extension) lose their old TOFU pin and
   fall through to IXPSK0 / plain Noise. Schedule a cert rotation
   that re-signs every host with `-rp-pubkey-from` (or
   `-rp-pubkey-sha256`) set. This is typically a single Ansible
   roll: issue new certs, push them, HUP nebula on each host.

The on-disk PSK directory format (`<sha256-hex>.psk`, 32 bytes) is
unchanged, so no PSK migration is required.

### 6.2 From the embedded build to the sidecar build

The embedded build still works under `-tags rosenpass_embedded`; if
you want to move to the default (sidecar) build, stand up the
rosenpass daemon as described in section 2 and point nebula at
`pki.pq_psk_dir` instead of relying on `pq.embedded_rosenpass`.
There is no flag-day requirement — the two build modes interoperate
on the wire (both speak IXPSK2 with 32-byte PSKs derived by the
same protocol).

## 7. Disk hygiene: put the PSK directory on tmpfs

### Threat model

The PQ PSK layer exists to close the harvest-now-decrypt-later (HNDL)
window: an adversary recording encrypted traffic today cannot decrypt it
later even if they later obtain a cryptographically relevant quantum
computer. PSK files on a persistent disk reopen a portion of that
window: if the disk is imaged or stolen, the attacker obtains the live
PSK and can immediately decrypt any recorded ciphertext from the epoch
those bytes were active. A volatile filesystem (tmpfs/ramfs) eliminates
this residual: PSK files vanish on power-off so an offline disk image
carries no useful key material.

### Nebula startup advisory

On Linux, nebula checks whether `pki.pq_psk_dir` resides on tmpfs or
ramfs at startup (and on each HUP that changes the path). If the
directory is on a persistent filesystem, nebula logs an `Info`-level
message at startup:

```
pki.pq_psk_dir is not on tmpfs/ramfs; PSK material will survive
power-off. Consider a tmpfs mount — see the operator guide's
disk-hygiene section  dir=/var/lib/nebula/pq_psk
```

This check is advisory only — nebula continues normally. On non-Linux
platforms the check is skipped and no message is emitted.

### Recommended: systemd TemporaryFileSystem drop-in

The easiest way to move the PSK directory to tmpfs on a systemd host
is a drop-in on the nebula unit (or on the rosenpass unit, if rosenpass
writes the files):

```ini
# /etc/systemd/system/rosenpass.service.d/tmpfs.conf
[Service]
TemporaryFileSystem=/var/run/rosenpass/psk:mode=0700
```

`TemporaryFileSystem` mounts a private tmpfs at the given path for the
service's lifetime. Adjust the path to match your `pki.pq_psk_dir` and
make it readable by the nebula user (group-based sharing works the same
as with a regular directory — add both users to a shared group and set
mode `2770`).

Alternatively, a dedicated tmpfs mount unit or an fstab entry works
equally well:

```ini
# /etc/systemd/system/nebula-psk.mount  (example mount unit)
[Unit]
Description=tmpfs for nebula PQ PSK files

[Mount]
What=tmpfs
Where=/var/lib/nebula/pq_psk
Type=tmpfs
Options=mode=0770,uid=rosenpass,gid=nebula-psk,nosuid,nodev,noexec

[Install]
WantedBy=multi-user.target
```

### Interaction with cold-start provisioning

tmpfs is cleared on every reboot, so nebula starts against an empty
`pki.pq_psk_dir` until the rosenpass sidecar completes its first key
exchange and writes the initial PSK files. This is the documented
provisioning state:

- The `pq_psk_stale_warn` watchdog stays silent on a truly empty
  directory (no files = no stale files; the timer only arms once a
  PSK has been observed).
- The `pq.responder_psk_deferred` counter (in the metrics) counts
  cold-start deferrals: handshakes where the local side had no PSK
  yet and fell back to IXPSK0. Once the sidecar's first KEX
  completes and nebula's fsnotify watcher picks up the new file, the
  counter stops climbing and subsequent handshakes use IXPSK2.
- Nebula logs the Info advisory at startup regardless of whether the
  directory is empty — the check is on the filesystem type, not the
  file count.

In `pq.mode: required` deployments, a cold-start empty directory will
block handshakes with peers for which PSK material is expected. Either
tolerate a brief window of `opportunistic` mode immediately after
reboot (switch to `required` once the sidecar has run its first KEX),
or provision an initial PSK archive that the systemd unit restores into
the tmpfs before nebula starts.

### Memory-hygiene boundary

nebula wipes its transient copy of each PSK immediately after
installing it into the Noise handshake state (see `pq/wipe.go`). The
provider snapshots — current epoch and previous epoch — remain in
memory by design, because they must be available for the lifetime of
the tunnels that used them. The chain keys held inside the
`flynn/noise` library cannot be wiped from outside the library without
patching the dependency. The tmpfs recommendation above addresses
at-rest exposure on disk; in-memory exposure remains for the life of
the nebula process and is an accepted residual given the threat model.

## 8. Rotation skew and multi-epoch tolerance

Rosenpass rotates each peer's PSK on its own clock (default ~2 minutes).
The two sides of a tunnel never rewrite their `.psk` files at the same
instant: for a brief window one side has already advanced to epoch *k+1*
while the other still holds epoch *k*. With a single stored PSK that
window is a hard outage — both sides hold *valid but different* keys, so
every IXPSK2 handshake fails its msg2 AEAD check until the lagging file
lands.

Nebula closes that window automatically. The `FileProvider` keeps the
**previous epoch's** PSK per peer in memory (a fixed window of 2: current
+ previous), populated whenever a rescan observes a peer's `.psk` bytes
change. Both skew directions then self-heal with no operator action and
no configuration:

- **Responder behind** (the initiator already rotated): the initiator's
  msg2 AEAD check fails, which uniquely identifies an epoch mismatch (the
  peer is reachable and answering, the key bytes just differ). The
  handshake manager swaps the previous-epoch PSK onto the live Noise
  machine and re-processes the *same* msg2 packet — a zero-extra-round-trip
  retry. `flynn/noise` checkpoints and rolls its symmetric state back on a
  failed read, so this is safe. One swap per handshake cycle.
- **Initiator behind** (the responder already rotated): the responder
  cannot see which epoch the initiator holds (msg1 carries no PSK
  material), so it infers skew from timing. A fresh msg1 arriving within
  30s of a current-epoch msg2 we just sent the same peer is read as "the
  initiator rejected our msg2"; the responder answers the retransmit with
  its previous-epoch PSK once, then flips back to current. This is a
  bounded in-memory hint cache (`pq/altepoch.go`), never a downgrade to
  IXPSK0.

Healing **never** falls through to a non-PQ handshake — there is no
downgrade lever. A peer holding neither the current nor the previous
epoch simply times out (see the control behaviour proven in the e2e
suite).

### Security cost

Tolerance of the previous epoch means a compromised epoch-*k* PSK stays
acceptable for **one extra rotation period** — it dies at *k+2* instead of
*k+1*. With rosenpass's default ~2-minute rekey this is a few minutes of
extra exposure for a key that was already post-quantum-derived. The
window is fixed at 2 and is not configurable; that bound *is* the design.

### Restart behaviour

The previous epoch lives only in memory. A nebula restart drops it, which
is fine: a restart triggers fresh handshakes against the current epoch
anyway, and the skew window is seconds-to-minutes.

### Observability

| metric | meaning |
|---|---|
| `pq.handshake_ixpsk2_msg2_reject` | initiator saw an epoch mismatch (peer alive, PSK bytes differ). The definitive skew / broken-pairing signal — stronger than the timeout counter. |
| `pq.psk_prev_epoch_recovered` | a handshake completed on the previous-epoch PSK (either heal direction). A steady low rate is normal rotation skew; a high sustained rate means sidecar file delivery is chronically lagging. |
| `pq.handshake_ixpsk2_timed_out` | no shared epoch (or peer dead) — healing could not help. |

The `pq-status` ssh command surfaces the same picture per peer (see
below).

### `pq-status` ssh command

Nebula's built-in ssh server gains a `pq-status` command reporting
per-peer PQ state: handshake subtype (`ix` / `ix_psk2`), whether a PSK
and a retained previous epoch are present, the live binding verdict
(`ok` / `mismatch` / `cert-only` / `hint-only` / `none`, computed at
query time from the CA-signed cert extension versus the local provider
hint), and the per-peer IXPSK2 reject/timeout counts. `-json` (or
`-pretty`) emits the same data plus a provider-level view:

```
$ ssh -p <ssh_port> nebula@<host> pq-status
10.0.0.2  name=lighthouse subtype=ix_psk2 psk=true prev=true binding=ok rejects=1 timeouts=0
10.0.0.3  name=edge-1     subtype=ix_psk2 psk=true prev=false binding=ok rejects=0 timeouts=0
```

A peer stuck at `binding=mismatch`, a climbing `rejects` count, or
`psk=false` on a peer that should have one are the signatures to watch
when diagnosing a wedged PQ tunnel.
