# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2021-05-11

### Added

- Ability to output qr code images in `print`, `ca`, and `sign` modes for `nebula-cert`.
  This is useful when configuring mobile clients. (#297)

- Experimental: Nebula can now do work on more than 2 cpu cores in send and receive paths via
  the new `routines` config option. (#382, #391, #395)
  
- ICMP ping requests can be responded to when the `tun.disabled` is `true`.
  This is useful so that you can "ping" a lighthouse running in this mode. (#342)

- Run smoke tests via `make smoke-docker`. (#287)

- More reported stats, udp memory use on linux, build version (when using Prometheus), firewall, 
  handshake, and cached packet stats. (#390, #405, #450, #453)

- IPv6 support for the underlay network. (#369)

- End to end testing, run with `make e2e`. (#425, #427, #428)

### Changed

- Darwin will now log stdout/stderr to a file when using `-service` mode. (#303)

- Example systemd unit file now better arranged startup order when using `sshd`
  and other fixes. (#317, #412, #438)
  
- Reduced memory utilization/garbage collection. (#320, #323, #340)

- Reduced CPU utilization. (#329)

- Build against go 1.16. (#381)

- Refactored handshakes to improve performance and correctness. (#401, #402, #404, #416, #451)

- Improved roaming support for mobile clients. (#394, #457)

- Lighthouse performance and correctness improvements. (#406, #418, #429, #433, #437, #442, #449)

- Better ordered startup to enable `sshd`, `stats`, and `dns` subsystems to listen on
  the nebula interface. (#375)

### Fixed

- No longer report handshake packets as `lost` in stats. (#331)

- Error handling in the `cert` package. (#339, #373)

- Orphaned pending hostmap entries are cleaned up. (#344)

- Most known data races are now resolved. (#396, #400, #424)

- Refuse to run a lighthouse on an ephemeral port. (#399)

- Removed the global references. (#423, #426, #446)

- Reloading via ssh command avoids a panic. (#447)

- Shutdown is now performed in a cleaner way. (#448)

- Logs will now find their way to Windows event viewer when running under `-service` mode
  in Windows. (#443)

## [1.3.0] - 2020-09-22

### Added

- You can emit statistics about non-message packets by setting the option
  `stats.message_metrics`. You can similarly emit detailed statistics about
  lighthouse packets by setting the option `stats.lighthouse_metrics`. See
  the example config for more details. (#230)

- We now support freebsd/amd64. This is experimental, please give us feedback.
  (#103)

- We now release a binary for `linux/mips-softfloat` which has also been
  stripped to reduce filesize and hopefully have a better chance on running on
  small mips devices. (#231)

- You can set `tun.disabled` to true to run a standalone lighthouse without a
  tun device (and thus, without root). (#269)

- You can set `logging.disable_timestamp` to remove timestamps from log lines,
  which is useful when output is redirected to a logging system that already
  adds timestamps. (#288)

### Changed

- Handshakes should now trigger faster, as we try to be proactive with sending
  them instead of waiting for the next timer tick in most cases. (#246, #265)

- Previously, we would drop the conntrack table whenever firewall rules were
  changed during a SIGHUP. Now, we will maintain the table and just validate
  that an entry still matches with the new rule set. (#233)

- Debug logs for firewall drops now include the reason. (#220, #239)

- Logs for handshakes now include the fingerprint of the remote host. (#262)

- Config item `pki.blacklist` is now `pki.blocklist`. (#272)

- Better support for older Linux kernels. We now only set `SO_REUSEPORT` if
  `tun.routines` is greater than 1 (default is 1). We also only use the
  `recvmmsg` syscall if `listen.batch` is greater than 1 (default is 64).
  (#275)

- It is possible to run Nebula as a library inside of another process now.
  Note that this is still experimental and the internal APIs around this might
  change in minor version releases. (#279)

### Deprecated

- `pki.blacklist` is deprecated in favor of `pki.blocklist` with the same
   functionality. Existing configs will continue to load for this release to
   allow for migrations. (#272)

### Fixed

- `advmss` is now set correctly for each route table entry when `tun.routes`
  is configured to have some routes with higher MTU. (#245)

- Packets that arrive on the tun device with an unroutable destination IP are
  now dropped correctly, instead of wasting time making queries to the
  lighthouses for IP `0.0.0.0` (#267)

## [1.2.0] - 2020-04-08

### Added

- Add `logging.timestamp_format` config option. The primary purpose of this
  change is to allow logging timestamps with millisecond precision. (#187)

- Support `unsafe_routes` on Windows. (#184)

- Add `lighthouse.remote_allow_list` to filter which subnets we will use to
  handshake with other hosts. See the example config for more details. (#217)

- Add `lighthouse.local_allow_list` to filter which local IP addresses and/or
  interfaces we advertise to the lighthouses. See the example config for more
  details. (#217)

- Wireshark dissector plugin. Add this file in `dist/wireshark` to your
  Wireshark plugins folder to see Nebula packet headers decoded. (#216)

- systemd unit for Arch, so it can be built entirely from this repo. (#216)

### Changed

- Added a delay to punching via lighthouse signal to deal with race conditions
  in some linux conntrack implementations. (#210)

  See deprecated, this also adds a new `punchy.delay` option that defaults to `1s`.

- Validate all `lighthouse.hosts` and `static_host_map` VPN IPs are in the
  subnet defined in our cert. Exit with a fatal error if they are not in our
  subnet, as this is an invalid configuration (we will not have the proper
  routes set up to communicate with these hosts). (#170)

- Use absolute paths to system binaries on macOS and Windows. (#191)

- Add configuration options for `handshakes`. This includes options to tweak
  `try_interval`, `retries` and `wait_rotation`. See example config for
  descriptions. (#179)

- Allow `-config` file to not end in `.yaml` or `yml`. Useful when using
  `-test` and automated tools like Ansible that create temporary files without
  suffixes. (#189)

- The config test mode, `-test`, is now more thorough and catches more parsing
  issues. (#177)

- Various documentation and example fixes. (#196)

- Improved log messages. (#181, #200)

- Dependencies updated. (#188)

### Deprecated

- `punchy`, `punch_back` configuration options have been collapsed under the
  now top level `punchy` config directive. (#210)

  `punchy.punch` - This is the old `punchy` option. Should we perform NAT hole
  punching (default false)?

  `punchy.respond` - This is the old `punch_back` option. Should we respond to
  hole punching by hole punching back (default false)?

### Fixed

- Reduce memory allocations when not using `unsafe_routes`. (#198)

- Ignore packets from self to self. (#192)

- MTU fixed for `unsafe_routes`. (#209)

## [1.1.0] - 2020-01-17

### Added

- For macOS and Windows, build a special version of the binary that can install
  and manage its own service configuration. You can use this with `nebula
  -service`.  If you are building from source, use `make service` to build this feature.
- Support for `mips`, `mips64`, `386` and `ppc64le` processors on Linux.
- You can now configure the DNS listen host and port with `lighthouse.dns.host`
  and `lighthouse.dns.port`.
- Subnet and routing support. You can now add a `unsafe_routes` section to your
  config to allow hosts to act as gateways to other subnets. Read the example
  config for more details. This is supported on Linux and macOS.

### Changed

- Certificates now have more verifications performed, including making sure
  the certificate lifespan does not exceed the lifespan of the root CA. This
  could cause issues if you have signed certificates with expirations beyond
  the expiration of your CA, and you will need to reissue your certificates.
- If lighthouse interval is set to `0`, never update the lighthouse (mobile
  optimization).
- Various documentation and example fixes.
- Improved error messages.
- Dependencies updated.

### Fixed

- If you have a firewall rule with `group: ["one-group"]`, this will
  now be accepted, with a warning to use `group: "one-group"` instead.
- The `listen.host` configuration option was previously ignored (the bind host
  was always 0.0.0.0). This option will now be honored.
- The `ca_sha` and `ca_name` firewall rule options should now work correctly.

## [1.0.0] - 2019-11-19

### Added

- Initial public release.

[Unreleased]: https://github.com/slackhq/nebula/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/slackhq/nebula/releases/tag/v1.4.0
[1.3.0]: https://github.com/slackhq/nebula/releases/tag/v1.3.0
[1.2.0]: https://github.com/slackhq/nebula/releases/tag/v1.2.0
[1.1.0]: https://github.com/slackhq/nebula/releases/tag/v1.1.0
[1.0.0]: https://github.com/slackhq/nebula/releases/tag/v1.0.0
