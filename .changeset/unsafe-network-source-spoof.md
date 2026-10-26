---
default: patch
---

A peer whose certificate carries an unsafe network overlapping the overlay could send packets as any node in it: the firewall accepted any source inside the unsafe network. A source address inside this node's own networks must now be the sending peer's own; through an unsafe network it is dropped, counted as a dropped remote address. A peer whose unsafe network deliberately covers this node's overlay range therefore no longer delivers packets from non-nebula hosts in that range either.
