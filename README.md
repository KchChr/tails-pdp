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
```

## Admin Tool

The admin tool operates on the pinned maps directly and can be built and run separately:

```shell
cargo build --bin tails-pdp-admintool --release
./target/release/tails-pdp-admintool --help
```

Typical commands:

Show all policies:

```shell
./target/release/tails-pdp-admintool show
```

Show only active policies:

```shell
./target/release/tails-pdp-admintool show-active
```

Clear one file-open static policy:

```shell
sudo ./target/release/tails-pdp-admintool clear 0 --action file-open
```

Clear one file-open stream policy:

```shell
sudo ./target/release/tails-pdp-admintool clear-stream 0 --action file-open
```

Set one file-open static policy:

```shell
sudo ./target/release/tails-pdp-admintool set 0 \
  --entitlement deny \
  --action file-open \
  --subject 1000 \
  --command cat \
  --resource /home/hntr/test.txt
```

Set one file-open stream policy:

```shell
sudo ./target/release/tails-pdp-admintool set-stream 0 \
  --entitlement permit \
  --action file-open \
  --subject 1000 \
  --attribute time \
  --resource /home/hntr/test.txt \
  --operator less-than \
  --modulo 10 \
  --value 5
```

Set one socket-bind static policy:

```shell
sudo ./target/release/tails-pdp-admintool set 0 \
  --entitlement deny \
  --action socket-bind \
  --subject 1000 \
  --family inet \
  --transport tcp \
  --resource 0.0.0.0 \
  --port 8080
```

Set one socket-bind stream policy:

```shell
sudo ./target/release/tails-pdp-admintool set-stream 0 \
  --entitlement permit \
  --action socket-bind \
  --subject 1000 \
  --attribute time \
  --family inet \
  --transport tcp \
  --resource 0.0.0.0 \
  --port 8080 \
  --operator less-than \
  --modulo 10 \
  --value 5
```

Notes:

- `show` and `show-active` do not require `sudo`
- `clear`, `clear-stream`, `set`, `set-stream`, `load-examples`, and `load-stream-examples`
  require `sudo`
- `action` is always the LSM hook the policy belongs to, for example `file-open`
- `index` in `clear`, `clear-stream`, `set`, and `set-stream` is hook-local
- there are separate pinned maps per hook:
  `FILE_OPEN_STATIC_POLICIES`, `FILE_OPEN_STREAM_POLICIES`,
  `SOCKET_BIND_STATIC_POLICIES`, and `SOCKET_BIND_STREAM_POLICIES`
- for file policies, `--resource` is given as a path in userspace; when the policy is loaded, the
  loader resolves that path to `device + inode`, and the kernel matches on those values
- for `socket-bind`, `--resource` is the local bind address, `--family` is `inet` or `inet6`,
  `--transport` is `tcp` or `udp`, and `--port` is the local port
- `0.0.0.0` matches any IPv4 address for the selected port and transport
- `::` matches any IPv6 address for the selected port and transport

## Stream Policies

Stream policies are managed through `tails-pdp-admintool`.

Example: allow subject `1000` to access `/home/hntr/test.txt` via `file_open` for five seconds
out of every ten seconds:

```shell
sudo ./target/release/tails-pdp-admintool set-stream 0 \
  --entitlement permit \
  --action file-open \
  --subject 1000 \
  --attribute time \
  --resource /home/hntr/test.txt \
  --operator less-than \
  --modulo 10 \
  --value 5
```

This example means:

- subject `1000`
- action `file_open`
- resource `/home/hntr/test.txt`
- evaluate `time % 10 < 5`
- if the condition is true: `Permit`
- if the condition is false: inverse decision, therefore `Deny`

To remove stream policies again:

```shell
sudo ./target/release/tails-pdp-admintool clear-stream 0 --action file-open
sudo ./target/release/tails-pdp-admintool clear-stream 1 --action file-open
sudo ./target/release/tails-pdp-admintool clear-stream 2 --action file-open
```

To load the built-in example stream policies:

```shell
sudo ./target/release/tails-pdp-admintool load-stream-examples
```

You can inspect the currently loaded stream policies with:

```shell
./target/release/tails-pdp-admintool show
./target/release/tails-pdp-admintool show-active
```

## Socket-Bind Policies

`socket_bind` policies control which local address/port combinations a subject may bind.

Example: deny UID `1000` from binding any IPv4 TCP socket on local port `8080`:

```shell
sudo ./target/release/tails-pdp-admintool set 0 \
  --entitlement deny \
  --action socket-bind \
  --subject 1000 \
  --family inet \
  --transport tcp \
  --resource 0.0.0.0 \
  --port 8080
```

Time-based example: permit UID `1000` to bind `0.0.0.0:8080/tcp` only when `time % 10 < 5`:

```shell
sudo ./target/release/tails-pdp-admintool set-stream 0 \
  --entitlement permit \
  --action socket-bind \
  --subject 1000 \
  --attribute time \
  --family inet \
  --transport tcp \
  --resource 0.0.0.0 \
  --port 8080 \
  --operator less-than \
  --modulo 10 \
  --value 5
```

This means:

- subject `1000`
- action `socket_bind`
- family `inet`
- transport `tcp`
- local address `0.0.0.0`, therefore any IPv4 address
- local port `8080`
- evaluate `time % 10 < 5`
- if the condition is true: `Permit`
- if the condition is false: inverse decision, therefore `Deny`

## Debugging

To inspect kernel debug output from `bpf_printk!`:

```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Run that in a second terminal while `tails-pdp` is running.

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
