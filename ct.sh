#!/bin/sh
set -e
cd "$(dirname "$0")/mbedtls"

cargo test
cargo test --features spin_threading
cargo test --features rust_threading
cargo test --features zlib
cargo +$CORE_IO_NIGHTLY test --no-default-features --features core_io,rdrand
cargo +nightly build --target=x86_64-fortanix-unknown-sgx --features=sgx --no-default-features
