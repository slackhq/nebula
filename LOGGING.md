### Logging conventions

A log message (the string/format passed to `Info`, `Error`, `Debug` etc, as well as their `Sprintf` counterparts) should
be a descriptive message about the event and may contain specific identifying characteristics. Regardless of the
level of detail in the message identifying characteristics should always be included via `WithField`, `WithFields` or
`WithError`

If an error is being logged use `l.WithError(err)` so that there is better discoverability about the event as well
as the specific error condition.

#### Common fields

- `cert` - a `cert.NebulaCertificate` object, do not `.String()` this manually, `logrus` will marshal objects properly
  for the formatter it is using.
- `fingerprint` - a single `NebeulaCertificate` hex encoded fingerprint
- `fingerprints` - an array of `NebulaCertificate` hex encoded fingerprints
- `fwPacket` - a FirewallPacket object
- `handshake` - an object containing:
    - `stage` - the current stage counter
    - `style` - noise handshake style `ix_psk0`, `xx`, etc
- `header` - a nebula header object
- `udpAddr` - a `net.UDPAddr` object
- `udpIp` - a udp ip address
- `vpnIp` - vpn ip of the host (remote or local)
- `relay` - the vpnIp of the relay host that is or should be handling the relay packet
- `relayFrom` - The vpnIp of the initial sender of the relayed packet 
- `relayTo` - The vpnIp of the final destination of a relayed packet

#### Example:

```
l.WithError(err).
    WithField("vpnIp", IntIp(hostinfo.hostId)).
    WithField("udpAddr", addr).
    WithField("handshake", m{"stage": 1, "style": "ix"}).
    Info("Invalid certificate from host")
```