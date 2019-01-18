#!/bin/sh
set -e
cd "$(dirname "$0")/mbedtls"

cargo test
cargo test --features spin_threading
cargo test --features zlib
cargo +$CORE_IO_NIGHTLY test --no-default-features --features core_io,rdrand
