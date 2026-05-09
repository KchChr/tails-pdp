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

If pinned map layouts changed, remove the stale maps once before restarting:

```shell
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME_ISO8601
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_DEFCON
sudo rm -f /sys/fs/bpf/tails-pdp/POLICY_GENERATION
```

## Admin Tool

Policies are no longer loaded through `tails-pdp-admintool`.

The active source of truth is the repository-local `policies/` directory. The userspace loader:

- loads all `.sapl` files from `./policies` on startup
- rescans the directory every second
- recompiles the full directory contents on change
- fully reconciles the four pinned policy maps on successful compilation
- keeps the last successfully applied policy generation if a changed file cannot be parsed or
  compiled
- removes policies from the maps again when the corresponding `.sapl` file disappears from
  `./policies`

Only files ending in `.sapl` are loaded. The `examples/` directory is not loaded automatically.

## Policy Files

Each file contains exactly one SAPL-inspired policy document:

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
- one `action == "file_open"` or `action == "socket_bind"` condition
- simple conjunction by writing multiple semicolon-terminated statements
- optional `subject.uid`
- `file_open` fields:
  `command`, `resource.path`
- `socket_bind` fields:
  `resource.family`, `resource.transport`, `resource.ip`, `resource.port`
- one optional stream condition per policy:
  `environment.time % N <op> VALUE`
  `environment.utc.hour <op> VALUE`
  `environment.utc.minute <op> VALUE`
  `environment.utc.second <op> VALUE`
  `environment.defcon.level <op> VALUE`

`environment.defcon.level` reads the current test DEFCON level from
`stream-attributes/DEFCON.txt`. Valid values are integers from `1` to `5`. The userspace process
watches this file and writes valid changes to the pinned `CURRENT_DEFCON` eBPF map.

Not supported:

- `import`
- `schema`
- `var`
- `obligation`
- `advice`
- `transform`
- `or`
- multiple stream conditions inside one file

Complex behavior is intentionally expressed by multiple files. Example: “deny before 08:00 and
from 16:00 onwards” is represented by two policies.

Example `socket_bind` stream policy:

```sapl
policy "deny socket_bind on 0.0.0.0:8443 before 08 UTC"
deny
    action == "socket_bind";
    resource.family == "inet";
    resource.ip == "0.0.0.0";
    resource.port == 8443;
    environment.utc.hour < 8;
```

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
cp examples/10-file-open-static-deny-cat-test.sapl policies/
cp examples/13-file-open-stream-deny-before-08.sapl policies/
cp examples/14-file-open-stream-deny-after-16.sapl policies/
```

After at most one second, the loader detects the change and rewrites the pinned maps.

Example DEFCON workflow:

```shell
cp examples/15-file-open-stream-deny-defcon-le-2.sapl policies/
echo 5 > stream-attributes/DEFCON.txt
cat /home/hntr/test.txt
echo 2 > stream-attributes/DEFCON.txt
cat /home/hntr/test.txt
```

With the example policy active, DEFCON `5` does not trigger the deny condition. DEFCON `2` does.

## Examples

The repository ships example policies in `examples/`.

Current examples cover:

- `file_open` static deny for `cat`
- `file_open` modulo-based stream permit
- `file_open` deny before 08:00 UTC
- `file_open` deny from 16:00 UTC onwards
- `file_open` deny at DEFCON 2 or lower
- `socket_bind` static deny on `0.0.0.0:8080/tcp`
- `socket_bind` modulo-based stream permit
- `socket_bind` deny before 08:00 UTC
- `socket_bind` deny from 16:00 UTC onwards
- `socket_bind` deny at DEFCON 2 or lower

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
- mutating admin-tool commands still operate on the pinned maps directly, but they are no longer
  the source of truth and will be overwritten by the next successful sync from `./policies`
- there are separate pinned maps per hook:
  `FILE_OPEN_STATIC_POLICIES`, `FILE_OPEN_STREAM_POLICIES`,
  `SOCKET_BIND_STATIC_POLICIES`, and `SOCKET_BIND_STREAM_POLICIES`
- for file policies, `--resource` is given as a path in userspace; when the policy is loaded, the
  loader resolves that path to `device + inode`, and the kernel matches on those values
- for `socket-bind`, `--resource` is the local bind address, `--family` is `inet` or `inet6`,
  `--transport` is `tcp` or `udp`, and `--port` is the local port
- `0.0.0.0` matches any IPv4 address for the selected port and transport
- `::` matches any IPv6 address for the selected port and transport
- stream attributes accepted by the admin tool are `time`, `hour`, `minute`, `second`, and `defcon`

## Monitoring

The userspace monitor observes active file descriptors and `socket_bind` states.

It:

- scans `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`
- maps socket inodes back to processes via `/proc/<pid>/fd`
- maps file descriptors back to file `device + inode` identities
- evaluates the same policy logic as the eBPF side
- logs violations on the command line

For file violations, the monitor currently tries to close only the offending file descriptors in the
affected process.

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

Test a `socket_bind` policy with Python:

```shell
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(('0.0.0.0', 8080)); print('bind ok')"
```

Notes:

- `ls -li` is a quick way to see the inode.
- `stat -c 'inode=%i dev_dec=%d dev_hex=%D ...'` shows the inode and the raw device value from
  the shell.
- `stat -c 'major=%t minor=%T ...'` shows the device split into major/minor numbers, which is
  useful when comparing filesystem identities manually.
- the Python one-liner is a quick way to test whether a `socket_bind` policy allows or denies a
  local bind on a specific address and port.
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
