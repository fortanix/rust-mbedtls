#!/bin/sh
set -e
cd "$(dirname "$0")/mbedtls"

cargo +stable test
cargo +stable test --features spin_threading
# Pinned to this particular nightly version because of core_io. This can be
# re-pinned whenever core_io is updated to the latest nightly.
cargo +nightly-2018-03-07 test --no-default-features --features core_io,rdrand
