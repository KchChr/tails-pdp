# Stream Attributes

This directory contains userspace-maintained stream attributes.

`DEFCON.txt` contains the current DEFCON level as a single integer from `1` to `5`.
The loader watches this file and writes valid changes to the pinned `CURRENT_DEFCON` eBPF map.

Structured attributes are read from:

- `system.env` for global attributes, for example `defcon = 3`
- `subjects/<uid>.env` for subject-specific attributes, for example `position = "engineer"`

Structured attributes are written to the pinned `ATTRIBUTES` eBPF map and activated through
`ATTRIBUTE_GENERATION`.
