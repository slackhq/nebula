---
default: patch
---

Signing a v2 certificate with an empty name, a name longer than 253 bytes, or an empty group now fails. These certificates were signed successfully but could not be loaded.
