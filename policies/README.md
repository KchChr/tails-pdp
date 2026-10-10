# Active policies

Only `.policy` files in this directory and its subdirectories are loaded.
The runtime watches directory events with inotify. Publish a complete prepared file by
atomic replacement; there is no fixed debounce delay:

```sh
bash scripts/publish-config.sh examples/10-file-open-static-deny-cat-test.policy policies/10-file-open-static-deny-cat-test.policy
```

Run the command from the repository root. Do not overwrite an active file in place.
The helper writes a unique temporary file with an ignored extension beside the destination, closes it, then uses
`mv` (same-filesystem rename). Temporary files are ignored. Removal of an active file also
triggers reconciliation. Validation and activation occur asynchronously; publication
success is not confirmation that a policy was accepted. Invalid policies leave the
previous map generation active; consult the runtime log and `show-active`.

Each rename publishes one file, not a transaction spanning multiple files. The helper
preserves the destination permission bits when replacing it; ownership belongs to the
publishing process. It does not promise persistence across a power failure.
