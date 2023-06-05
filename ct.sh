#!/bin/bash
set -ex
cd "$(dirname "$0")"

cd "./mbedtls"

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi

if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
  wget https://more.musl.cc/10-20210301/x86_64-linux-musl/aarch64-linux-musl-cross.tgz -O /tmp/aarch64-linux-musl-cross.tgz
  echo "c8ee0e7fd58f5ec6811e3cec5fcdd8fc47cb2b49fb50e9d7717696ddb69c812547b5f389558f62dfbf9db7d6ad808a5a515cc466b8ea3e9ab3daeb20ba1adf33  /tmp/aarch64-linux-musl-cross.tgz" | sha512sum -c
  tar -xf /tmp/aarch64-linux-musl-cross.tgz -C /tmp;
fi

export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11
export CC_aarch64_unknown_linux_musl=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64
export RUSTFLAGS="-A ambiguous_glob_reexports"

if [ "$TRAVIS_RUST_VERSION" == "stable" ] || [ "$TRAVIS_RUST_VERSION" == "beta" ] || [ "$TRAVIS_RUST_VERSION" == "nightly" ]; then
    # Install the rust toolchain
    rustup default $TRAVIS_RUST_VERSION
    rustup target add --toolchain $TRAVIS_RUST_VERSION $TARGET

    # The SGX target cannot be run under test like a ELF binary
    if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then 
        # make sure that explicitly providing the default target works
        cargo test --target $TARGET --release
        cargo test --features pkcs12 --target $TARGET
        cargo test --features pkcs12_rc2 --target $TARGET
        cargo test --features dsa --target $TARGET
        cargo test --test async_session --features=async-rt --target $TARGET
        cargo test --test async_session --features=async-rt,legacy_protocols --target $TARGET
        
        # If zlib is installed, test the zlib feature
        if [ -n "$ZLIB_INSTALLED" ]; then
            cargo test --features zlib --target $TARGET
            cargo test --test async_session --features=async-rt,zlib --target $TARGET
            cargo test --test async_session --features=async-rt,zlib,legacy_protocols --target $TARGET
        fi

        # If AES-NI is supported, test the feature
        if [ -n "$AES_NI_SUPPORT" ]; then
            cargo test --features force_aesni_support --target $TARGET
        fi

        # no_std tests only are able to run on x86 platform
        if [ "$TARGET" == "x86_64-unknown-linux-gnu" ]; then
            cargo test --no-default-features --features no_std_deps,rdrand,time --target $TARGET
            cargo test --no-default-features --features no_std_deps,rdrand --target $TARGET
        fi
    else
        cargo +$TRAVIS_RUST_VERSION test --no-run --target=$TARGET
    fi

else
    echo "Unknown version $TRAVIS_RUST_VERSION"
    exit 1
fi
