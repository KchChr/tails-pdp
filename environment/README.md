# Stream Attributes

This directory contains userspace-maintained stream attributes.

`DEFCON.txt` contains the current DEFCON level as a single integer from `1` to `5`.
The loader watches this file and writes valid changes to the pinned `CURRENT_DEFCON` eBPF map.
