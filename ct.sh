#!/bin/bash
set -ex
cd "$(dirname "$0")"

cd "./mbedtls"

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi

export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11

if [ $TRAVIS_RUST_VERSION = "stable" ] || [ $TRAVIS_RUST_VERSION = "beta" ] || [ $TRAVIS_RUST_VERSION = "nightly" ]; then
    rustup default $TRAVIS_RUST_VERSION
    rustup target add --toolchain $TRAVIS_RUST_VERSION $TARGET
    # The SGX target cannot be run under test like a ELF binary
    if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
        # make sure that explicitly providing the default target works
        cargo test --target $TARGET --release
        cargo test --features pkcs12 --target $TARGET
        cargo test --features pkcs12_rc2 --target $TARGET
        cargo test --features dsa --target $TARGET
        cargo test --features spin_threading --target $TARGET
        cargo test --features rust_threading --target $TARGET
        cargo test --features custom_time,custom_gmtime_r --target $TARGET
        # test the async support
        cargo test --test async_session --features=async-rt --target $TARGET

        # If zlib is installed, test the zlib feature
        if [ -n "$ZLIB_INSTALLED" ]; then
            cargo test --features zlib --target $TARGET
        fi

        # If AES-NI is supported, test the feature
        if [ -n "$AES_NI_SUPPORT" ]; then
            cargo test --features force_aesni_support --target $TARGET
        fi
    else
        cargo +$TRAVIS_RUST_VERSION test --no-run --target=$TARGET --features=sgx --no-default-features
    fi

elif [ $TRAVIS_RUST_VERSION = $CORE_IO_NIGHTLY ]; then
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features core-io,rdrand,time,custom_time,custom_gmtime_r
    cargo +$CORE_IO_NIGHTLY test --no-default-features --features core-io,rdrand
else
    echo "Unknown version $TRAVIS_RUST_VERSION"
    exit 1
fi
