# tails-pdp

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling to Intel/AMD Linux) rustup target: `rustup target add x86_64-unknown-linux-musl`
1. (if cross-compiling to ARM64 Linux) rustup target: `rustup target add aarch64-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Running On The Target System

The repository contains a simple helper script for the target machine:

```shell
./run.sh
```

This currently does:

```shell
git pull
cargo build --bin tails-pdp-admintool --release
cargo run --bin tails-pdp --release
```

## Tests

Run the unprivileged formatting, unit-test, lint, and Linux build checks with:

```shell
./test.sh
```

On a dedicated Linux target, run the real verifier, LSM attach, policy rollback, and enforcement
tests with root privileges:

```shell
sudo ./test-e2e.sh
```

The end-to-end test temporarily owns `/sys/fs/bpf/tails-pdp` and therefore refuses to run while
another `tails-pdp` process is active. It must not be used on a production host.

If pinned map layouts changed, remove the stale maps once before restarting:

```shell
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME
# Legacy pin from versions before the single-time-map migration:
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME_ISO8601
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTES
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION
sudo rm -f /sys/fs/bpf/tails-pdp/POLICY_GENERATION
```

## Admin Tool

Policies are no longer loaded through `tails-pdp-admintool`.

The active source of truth is the repository-local `policies/` directory. The userspace loader:

- loads all `.policy` files from `./policies` on startup
- rescans the directory every second
- translates the full directory contents into kernel-compatible map entries on change
- fully reconciles the two pinned `file_open` policy maps after successful validation
- keeps the last successfully applied policy generation if a changed file cannot be parsed or
  translated
- removes policies from the maps again when the corresponding `.policy` file disappears from
  `./policies`

Only files ending in `.policy` are loaded. The `examples/` directory is not loaded automatically.

## Policy Files

Each file contains exactly one ASBAC policy document:

```sapl
policy "deny cat on /home/hntr/test.txt for uid 1000"
deny
    action == "file_open";
    subject.uid == 1000;
    command == "cat";
    resource.path == "/home/hntr/test.txt";
```

Supported concepts:

- `policy "name"`
- entitlement `permit` or `deny`
- one `action == "file_open"` condition
- simple conjunction by writing multiple semicolon-terminated statements
- optional `subject.uid`
- optional `file_open` fields: `command`, `resource.path`
- stream conditions per policy:
  `environment.time % N <op> VALUE`
  `environment.utc.hour <op> VALUE`
  `environment.utc.minute <op> VALUE`
  `environment.utc.second <op> VALUE`
  `system.<attribute> <op> VALUE`
  `subject.<attribute> <op> VALUE`
  `resource.<attribute> <op> VALUE`

Stream policies may use the same static hook filters as static policies. Example: a `file_open`
stream policy may combine `command == "cat"` and `resource.path == "/home/hntr/test.txt"` with
`system.defcon <= 2`.

`system.<attribute>`, `subject.<attribute>`, and `resource.<attribute>` read external attributes
from `attributes/`. `system.attributes` contains global attributes. `subjects/<uid>.attributes` contains
attributes for a concrete UID. `resources/<path>.attributes` contains attributes for a concrete file
resource, where `<path>` is the absolute resource path without the leading `/`, plus a `.attributes`
suffix. For example, `/home/hntr/test.txt` is described by
`resources/home/hntr/test.txt.attributes`. The userspace process watches these files and writes valid
changes to the pinned `ATTRIBUTES` and `ATTRIBUTE_GENERATION` eBPF maps.

Example:

```ini
# attributes/system.attributes
defcon = 3

# attributes/subjects/1000.attributes
position = "engineer"
clearance = 2

# attributes/resources/home/hntr/test.txt.attributes
clearanceLevel = 3
classification = "internal"
```

The policy condition `subject.position == "engineer"` is resolved against the current request UID.
The condition `system.defcon <= 3` is resolved against the global attributes in
`system.attributes`.
The condition `resource.classification == "internal"` is resolved against the opened file resource
using its device and inode identity.

Not supported:

- `import`
- `schema`
- `var`
- `obligation`
- `advice`
- `transform`
- `or`
- more than four dynamic `system.*`/`subject.*`/`resource.*` attribute conditions per policy

Complex disjunctions are intentionally expressed by multiple files. Example: “deny before 08:00 and
from 16:00 onwards” is represented by two policies.

Example modulo-based stream policy:

```sapl
policy "permit file_open on /home/hntr/test.txt for uid 1000 when time modulo matches"
permit
    action == "file_open";
    subject.uid == 1000;
    resource.path == "/home/hntr/test.txt";
    environment.time % 10 < 5;
```

Example workflow:

```shell
cp examples/10-file-open-static-deny-cat-test.policy policies/
cp examples/13-file-open-stream-deny-before-08.policy policies/
cp examples/14-file-open-stream-deny-after-16.policy policies/
```

After at most one second, the loader detects the change and rewrites the pinned maps.

Example DEFCON workflow:

```shell
cp examples/15-file-open-stream-deny-defcon-le-2.policy policies/
printf 'defcon = 5\n' > attributes/system.attributes
cat /home/hntr/test.txt
printf 'defcon = 2\n' > attributes/system.attributes
cat /home/hntr/test.txt
```

With the example policy active, DEFCON `5` does not trigger the deny condition. DEFCON `2` does.
The policy also contains `command == "cat"`, so another program name would not match it.

Example structured attribute workflow:

```shell
cp examples/25-file-open-stream-deny-engineer-defcon-le-3.policy policies/
mkdir -p attributes/subjects
printf 'defcon = 3\n' > attributes/system.attributes
printf 'position = "engineer"\n' > attributes/subjects/1000.attributes
cat /home/hntr/test.txt
```

## Examples

The repository ships example policies in `examples/`.

Current examples cover:

- `file_open` static deny for `cat`
- `file_open` modulo-based stream permit
- `file_open` deny before 08:00 UTC
- `file_open` deny from 16:00 UTC onwards
- `file_open` deny at DEFCON 2 or lower

## Admin Tool

The admin tool is now primarily an inspection/debugging tool for the pinned maps:

```shell
cargo build --bin tails-pdp-admintool --release
./target/release/tails-pdp-admintool --help
```

Typical read-only commands:

Show all policies:

```shell
./target/release/tails-pdp-admintool show
```

Show only active policies:

```shell
./target/release/tails-pdp-admintool show-active
```

Notes:

- `show` and `show-active` do not require `sudo`
- the admin tool opens the pinned maps read-only
- static and stream policies use `FILE_OPEN_STATIC_POLICIES` and
  `FILE_OPEN_STREAM_POLICIES`
- for file policies, `--resource` is given as a path in userspace; when the policy is loaded, the
  loader resolves that path to `device + inode`, and the kernel matches on those values
- stream attributes accepted by the admin tool are `time`, `hour`, `minute`, and `second`; DEFCON is
  represented as the structured system attribute `system.defcon`

## Userspace PEP

The eBPF LSM hook is the kernelspace PEP for new `file_open` operations. The userspace PEP
re-evaluates file descriptors that were already open when policies or attributes changed.

It:

- maps file descriptors back to file `device + inode` identities
- evaluates the same policy logic as the eBPF side
- logs violations on the command line

For violations, the userspace PEP tries to close only the offending file descriptors in the affected
process.

## FD schließen

```
sudo gdb -q -p <PID> \
  -ex 'call (int) close(<FD>)' \
  -ex detach \
  -ex quit
```

## Debugging

Userspace logging is controlled with `RUST_LOG`. Without `RUST_LOG`, `tails-pdp` defaults to `info`.

```shell
RUST_LOG=debug sudo -E ./target/release/tails-pdp
```

Kernel debug output from `bpf_printk!` is disabled by default. Enable it explicitly:

```shell
TAILS_PDP_EBPF_DEBUG=1 RUST_LOG=info sudo -E ./target/release/tails-pdp
```

Then inspect the kernel trace output in a second terminal:

```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Useful checks during debugging:

Inode quickly:

```shell
ls -li /home/hntr/test.txt
```

Inode and raw device value:

```shell
stat -c 'inode=%i dev_dec=%d dev_hex=%D path=%n' /home/hntr/test.txt
```

Device as major/minor plus inode:

```shell
stat -c 'major=%t minor=%T inode=%i path=%n' /home/hntr/test.txt
```

All policies:

```shell
sudo ./target/release/tails-pdp-admintool show
```

Only active policies:

```shell
sudo ./target/release/tails-pdp-admintool show-active
```

Notes:

- `ls -li` is a quick way to see the inode.
- `stat -c 'inode=%i dev_dec=%d dev_hex=%D ...'` shows the inode and the raw device value from
  the shell.
- `stat -c 'major=%t minor=%T ...'` shows the device split into major/minor numbers, which is
  useful when comparing filesystem identities manually.
- For policy matching, the important values are the resolved `device + inode` pair stored in the
  policy map and the same pair read by the eBPF hook.

This lets you compare:

- the file's inode and device from `stat`
- the resolved `device` and `inode` stored in `FILE_OPEN_STATIC_POLICIES` or
  `FILE_OPEN_STREAM_POLICIES`
- the `bpf_printk!` output in `trace_pipe`

## Cross-compiling on macOS for Linux/NixOS

Cross compilation should work on both Intel and Apple Silicon Macs.

The Linux kernel version does not affect the Rust userspace target triple. For NixOS you only need
the target CPU architecture from the destination machine:

```shell
uname -m
```

Typical mappings:

- `x86_64` -> `x86_64-unknown-linux-musl`
- `aarch64` or `arm64` -> `aarch64-unknown-linux-musl`

```shell
cargo build-linux-x86_64
```

This builds:

- `target/x86_64-unknown-linux-musl/release/tails-pdp`
- `target/x86_64-unknown-linux-musl/release/tails-pdp-admintool`

For ARM64 targets use:

```shell
cargo build-linux-aarch64
```

If your local cross linker binary has a different name than the default musl-cross names, you can
override it per command:

```shell
cargo build --release --target x86_64-unknown-linux-musl \
  --config target.x86_64-unknown-linux-musl.linker=\"/path/to/your/linker\"
```

## License

With the exception of eBPF code, tails-pdp is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
