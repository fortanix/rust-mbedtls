#!/bin/bash
set -ex
cd "$(dirname "$0")"

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

if [ -z $RUST_VERSION ]; then
    echo "Expected RUST_VERSION to be set in env"
    exit 1
fi

# Test logic start from here
export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-18
export CMAKE_POLICY_VERSION_MINIMUM=3.5

cargo_nextest="cargo nextest run"
cargo_test="cargo test"

if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    cargo install cross --git https://github.com/cross-rs/cross
    cargo_nextest="cross test"
    cargo_test="cross test"
fi

cd "${repo_root}/mbedtls"
case "$RUST_VERSION" in
    stable|beta|nightly)
        # Install the rust toolchain
        rustup default $RUST_VERSION
        rustup target add --toolchain $RUST_VERSION $TARGET
        printenv

        # The SGX target cannot be run under test like a ELF binary
        if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
            # make sure that explicitly providing the default target works
            $cargo_nextest --target $TARGET --release
            $cargo_nextest --features pkcs12 --target $TARGET
            $cargo_nextest --features pkcs12_rc2 --target $TARGET
            $cargo_nextest --features dsa --target $TARGET
            $cargo_nextest --features x509 --target $TARGET
            $cargo_nextest --features ssl --target $TARGET

                # If AES-NI is supported, test the feature
            if [ -n "$AES_NI_SUPPORT" ]; then
                $cargo_nextest --features force_aesni_support --target $TARGET
                $cargo_nextest --features force_aesni_support,x509,ssl --target $TARGET
            fi

            # no_std tests only are able to run on x86 platform
            if [ "$TARGET" == "x86_64-unknown-linux-gnu" ] || [[ "$TARGET" =~ ^x86_64-pc-windows- ]]; then
                $cargo_nextest --no-default-features --features no_std_deps --target $TARGET
                $cargo_nextest --no-default-features --features no_std_deps,rdrand,time,x509 --target $TARGET
                $cargo_nextest --no-default-features --features no_std_deps,rdrand,time,ssl --target $TARGET
            fi
        else
            $cargo_test --no-run --target=$TARGET
            $cargo_test --no-run --features ssl --target=$TARGET
            $cargo_test --no-run --features x509 --target=$TARGET
        fi

        if [ "$TARGET" == "x86_64-apple-darwin" ]; then
            $cargo_nextest --no-default-features --features no_std_deps --target $TARGET
        fi
        # special case: mbedtls should compile successfully on windows only with `std` feature
        if [[ "$TARGET" =~ ^x86_64-pc-windows- ]]; then
            $cargo_nextest --no-default-features --features std --target $TARGET
        fi

        # The SGX target cannot be run under test like a ELF binary
        if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
            $cargo_nextest --test async_session --features=async-rt,ssl --target $TARGET
            $cargo_nextest --test async_session --features=async-rt,ssl,legacy_protocols --target $TARGET
            $cargo_nextest chrono --features=chrono,ssl,x509 --target $TARGET

            # If zlib is installed, test the zlib feature
            if [ -n "$ZLIB_INSTALLED" ]; then
                $cargo_nextest --features zlib --target $TARGET
                $cargo_nextest --test async_session --features=async-rt,ssl,zlib --target $TARGET
                $cargo_nextest --test async_session --features=async-rt,ssl,zlib,legacy_protocols --target $TARGET
            fi
        fi
        ;;
    *)
        # Default case: If RUST_VERSION does not match any of the above
        echo "Unknown version $RUST_VERSION"
        exit 1
        ;;
esac
