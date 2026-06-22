# Stream Attributes

This directory contains userspace-maintained stream attributes.

Structured attributes are read from:

- `system.attributes` for global attributes, for example `defcon = 3`
- `subjects/<uid>.attributes` for subject-specific attributes, for example `position = "engineer"`
- `resources/<path>.attributes` for file resource attributes, for example
  `resources/home/hntr/test.txt.attributes` for `/home/hntr/test.txt`

Structured attributes are written to the pinned `ATTRIBUTES` eBPF map and activated through
`ATTRIBUTE_GENERATION`.

DEFCON is represented as the structured system attribute `system.defcon` in `system.attributes`. Valid
values are numbers from `1` to `5`.
