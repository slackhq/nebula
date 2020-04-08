# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/slackhq/nebula/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/slackhq/nebula/releases/tag/v1.2.0
[1.1.0]: https://github.com/slackhq/nebula/releases/tag/v1.1.0
[1.0.0]: https://github.com/slackhq/nebula/releases/tag/v1.0.0
