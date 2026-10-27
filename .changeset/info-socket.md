---
default: minor
---

An info socket that serves the `identity` command over HTTP: `GET /v1/identity` for this node, `GET /v1/identity/<vpn addr>` for the host owning an address, and `/pem` under either for the certificate.
