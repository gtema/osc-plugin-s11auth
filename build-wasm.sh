#!/bin/sh
# Builds the plugin and leaves s11auth_wasm_plugin.wasm in the current dir,
# where dist expects its build outputs.
set -eu
rustup target add wasm32-unknown-unknown
cargo build --release --locked --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/s11auth_wasm_plugin.wasm .
