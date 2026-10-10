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

## Publishing updates

Prepare the complete file outside the active path, then publish it from the repository root:

```sh
printf 'defcon = 3\n' > /tmp/prepared.attributes
bash scripts/publish-config.sh /tmp/prepared.attributes attributes/system.attributes
```

The helper stages a unique temporary file with an ignored extension in the destination directory and atomically renames
it after closing it. There is no fixed debounce delay. Do not edit an active file in place.
The recursive watcher responds to publication/removal and ignores temporary-file writes.
Invalid input leaves the previous attribute generation active; verify activation in the
runtime log or administration tool. Multiple publications are not a shared transaction.
