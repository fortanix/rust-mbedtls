#!/bin/bash
set -ex
cd "$(dirname "$0")"

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi

# Test logic start from here
export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11
export CC_aarch64_unknown_linux_musl=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64

cd "${repo_root}/mbedtls"
case "$TRAVIS_RUST_VERSION" in
    stable|beta|nightly|nightly-2021-09-08)
        # Install the rust toolchain
        rustup default $TRAVIS_RUST_VERSION
        rustup target add --toolchain $TRAVIS_RUST_VERSION $TARGET
        printenv

        for FEAT in "" "x509," "ssl,"; do
            # The SGX target cannot be run under test like a ELF binary
            if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
                # make sure that explicitly providing the default target works
                cargo test --features "$FEAT" --target $TARGET --release
                cargo test --features "$FEAT"pkcs12 --target $TARGET
                cargo test --features "$FEAT"pkcs12_rc2 --target $TARGET
                cargo test --features "$FEAT"dsa --target $TARGET

                # If AES-NI is supported, test the feature
                if [ -n "$AES_NI_SUPPORT" ]; then
                    cargo test --features "$FEAT"force_aesni_support --target $TARGET
                fi

                # no_std tests only are able to run on x86 platform
                if [ "$TARGET" == "x86_64-unknown-linux-gnu" ] || [[ "$TARGET" =~ ^x86_64-pc-windows- ]]; then
                    cargo test --no-default-features --features "$FEAT"no_std_deps,rdrand,time --target $TARGET
                    cargo test --no-default-features --features "$FEAT"no_std_deps --target $TARGET
                fi
            else
                cargo +$TRAVIS_RUST_VERSION test --no-run --features "$FEAT" --target=$TARGET
            fi
        done

        if [ "$TARGET" == "x86_64-apple-darwin" ]; then
            cargo test --no-default-features --features no_std_deps --target $TARGET
        fi
        # special case: mbedtls should compile successfully on windows only with `std` feature
        if [[ "$TARGET" =~ ^x86_64-pc-windows- ]]; then
            cargo test --no-default-features --features std --target $TARGET
        fi

        # The SGX target cannot be run under test like a ELF binary
        if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
            cargo test --test async_session --features=async-rt,ssl --target $TARGET
            cargo test --test async_session --features=async-rt,ssl,legacy_protocols --target $TARGET
            cargo test chrono --features=chrono,ssl,x509 --target $TARGET

            # If zlib is installed, test the zlib feature
            if [ -n "$ZLIB_INSTALLED" ]; then
                cargo test --features zlib --target $TARGET
                cargo test --test async_session --features=async-rt,ssl,zlib --target $TARGET
                cargo test --test async_session --features=async-rt,ssl,zlib,legacy_protocols --target $TARGET
            fi
        fi
        ;;
    *)
        # Default case: If TRAVIS_RUST_VERSION does not match any of the above
        echo "Unknown version $TRAVIS_RUST_VERSION"
        exit 1
        ;;
esac
