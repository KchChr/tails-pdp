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
