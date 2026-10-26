---
default: changed
---

`nebula-cert keygen` refuses to overwrite an existing `-out-key` or `-out-pub` file, matching `ca` and `sign`. Overwriting kept the old file's mode, so a key written over a world-readable file stayed world-readable.
