#!/bin/sh
set -ex
cd "$(dirname "$0")"

cd "./mbedtls"

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi

if [ $TRAVIS_RUST_VERSION = "stable" ] || [ $TRAVIS_RUST_VERSION = "beta" ] || [ $TRAVIS_RUST_VERSION = "nightly" ]; then
    rustup default $TRAVIS_RUST_VERSION
    # make sure that explicitly providing the default target works
    cargo test --target x86_64-unknown-linux-gnu
    cargo test --features zlib
    cargo test --features pkcs12
    cargo test --features pkcs12_rc2
    cargo test --features force_aesni_support

    rustup target add --toolchain $TRAVIS_RUST_VERSION x86_64-fortanix-unknown-sgx
    cargo +$TRAVIS_RUST_VERSION test --no-run --target=x86_64-fortanix-unknown-sgx

elif [ $TRAVIS_RUST_VERSION = $CORE_IO_NIGHTLY ]; then
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features no_std_deps,rdrand,time
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features no_std_deps,rdrand

else
    echo "Unknown version $TRAVIS_RUST_VERSION"
    exit 1
fi
