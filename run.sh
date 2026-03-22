#!/usr/bin/env bash

clear
git pull
cargo build --bin tails-pdp-admintool --release
cargo run --bin tails-pdp --release
