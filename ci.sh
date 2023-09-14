#!/bin/bash
set -ex
cd "$(dirname "$0")"

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi

# According to `mbedtls-sys/vendor/README.md`, need to install needed pkgs
python3 -m venv venv
source venv/bin/activate || source venv/Scripts/activate
python3 -m pip install -r ./mbedtls-sys/vendor/scripts/basic.requirements.txt

# Test logic start from here
export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11
export CC_aarch64_unknown_linux_musl=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64

cd "${repo_root}/mbedtls"
case "$TRAVIS_RUST_VERSION" in
    stable|beta|nightly)
        # Install the rust toolchain
        rustup default $TRAVIS_RUST_VERSION
        rustup target add --toolchain $TRAVIS_RUST_VERSION $TARGET
        printenv

        # The SGX target cannot be run under test like a ELF binary
        if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then
            # make sure that explicitly providing the default target works
            cargo nextest run --target $TARGET --release
            cargo nextest run --features dsa --target $TARGET
            cargo nextest run --features async-rt,tls13 --target $TARGET

            # If AES-NI is supported, test the feature
            if [ -n "$AES_NI_SUPPORT" ]; then
                cargo nextest run --features force_aesni_support,tls13 --target $TARGET
            fi
            # no_std tests only are able to run on x86 platform
            if [ "$TARGET" == "x86_64-unknown-linux-gnu" ] || [ "$TARGET" == "x86_64-apple-darwin" ] || [[ "$TARGET" =~ ^x86_64-pc-windows- ]]; then
                cargo nextest run --no-default-features --features no_std_deps,rdrand,time --target $TARGET
                cargo nextest run --no-default-features --features no_std_deps --target $TARGET
            fi

        else
            cargo +$TRAVIS_RUST_VERSION test --no-run --target=$TARGET
            cargo +$TRAVIS_RUST_VERSION test --no-default-features --features dsa,force_aesni_support,mpi_force_c_code,rdrand,std,time,tls13 --no-run --target=$TARGET
        fi
        ;;
    *)
        # Default case: If TRAVIS_RUST_VERSION does not match any of the above
        echo "Unknown version $TRAVIS_RUST_VERSION"
        exit 1
        ;;
esac
