#!/bin/sh
set -ex
cd "$(dirname "$0")"

cd "./mbedtls"

if [ $TOOLCHAIN = "stable" ] || [ $TOOLCHAIN = "beta" ]; then

    rustup toolchain add $TOOLCHAIN
    rustup default $TOOLCHAIN
    cargo test
    cargo test --features spin_threading
    cargo test --features rust_threading
    cargo test --features zlib
    cargo test --features pkcs12
    cargo test --features pkcs12_rc2
    cargo test --features force_aesni_support

elif [ $TOOLCHAIN = "coreio_nightly" ]; then

    rustup toolchain add $CORE_IO_NIGHTLY
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features core_io,rdrand,time,custom_time,custom_gmtime_r
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features core_io,rdrand

elif [ $TOOLCHAIN = "sgx" ]; then

    rustup toolchain add $SGX_NIGHTLY
    rustup target add --toolchain $SGX_NIGHTLY x86_64-fortanix-unknown-sgx
    cargo +$SGX_NIGHTLY test --no-run --target=x86_64-fortanix-unknown-sgx --features=sgx --no-default-features

fi
