#!/bin/sh
set -ex
cd "$(dirname "$0")"

if [ "${TRAVIS_BRANCH}" = "staging" ];
then
    rm -rf ./target
fi

cd "./mbedtls"

cargo test
cargo test --features spin_threading
cargo test --features rust_threading
cargo test --features zlib
cargo test --features pkcs12
cargo test --features pkcs12_rc2
cargo +$CORE_IO_NIGHTLY test --no-default-features --features core_io,rdrand
cargo +nightly build --target=x86_64-fortanix-unknown-sgx --features=sgx --no-default-features
