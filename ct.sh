#!/bin/sh
set -ex
cd "$(dirname "$0")"

cd "./mbedtls"

if [ $TRAVIS_RUST_VERSION = "stable" ] || [ $TRAVIS_RUST_VERSION = "beta" ]; then
    rustup default $TRAVIS_RUST_VERSION
    cargo test
    cargo test spin_threading
    cargo test rust_threading
    cargo test zlib
    cargo test pkcs12
    cargo test pkcs12_rc2
    cargo test force_aesni_support
    cargo build --no-default-features --features core_io,abort,cross-compile --target=thumbv7m-none-eabi

elif [ $TRAVIS_RUST_VERSION = $CORE_IO_NIGHTLY ]; then
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features mbedtls-test,core_io,rdrand,time,custom_time,custom_gmtime_r
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features mbedtls-test, core_io,rdrand

elif [ $TRAVIS_RUST_VERSION = $SGX_NIGHTLY ]; then
    rustup target add --toolchain $SGX_NIGHTLY x86_64-fortanix-unknown-sgx
    cargo +$SGX_NIGHTLY test --no-run --no-default-features --features mbedtls-test,sgx --target=x86_64-fortanix-unknown-sgx
fi
