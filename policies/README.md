This directory is the active policy source for `tails-pdp`.

Only files ending in `.sapl` are loaded.

The userspace loader scans this directory every second. If the full directory contents can be
parsed and compiled successfully, the four pinned eBPF policy maps are fully reconciled to match
the files in this directory. If parsing or compilation fails, the previously applied policy
generation remains active.

Copy example files from `../examples/` into this directory to activate them.
