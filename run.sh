#!/usr/bin/env bash

clear
git pull
cargo run --bin tails-pdp --release
cargo build --bin tails-pdp-admintool --release