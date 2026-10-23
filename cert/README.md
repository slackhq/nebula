## `cert`

This is a library for interacting with `nebula` style certificates and authorities.

There are now 2 versions of `nebula` certificates:

## v1

This version is deprecated.

A `protobuf` definition of the certificate format is included at `cert_v1.proto`

To compile the definition you will need `protoc` installed.

To compile for `go` with the same version of protobuf specified in go.mod:

```bash
make proto
```

## v2

This is the latest version which uses asn.1 DER encoding. It can support ipv4 and ipv6 and tolerate
future certificate changes better than v1.

`cert_v2.asn1` defines the wire format and can be used to compile marshalers.

## v3

A v2 certificate extended with post-quantum keys and a post-quantum CA signature. Its first fields are a byte exact
v2 certificate, so a v3 holder can present that v2 form to peers that only speak v2.

`cert_v3.asn1` defines the wire format, importing the v2 types from `cert_v2.asn1`.
