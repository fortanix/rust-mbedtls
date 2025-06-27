#!/bin/bash
set -ex
cd "$(dirname "$0")"

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

case "$RUST_VERSION" in
    stable|beta|nightly)
        echo "RUST_VERSION is valid: $RUST_VERSION"
        ;;
    *)
        echo "Error: RUST_VERSION must be one of stable, beta, or nightly. Found: '$RUST_VERSION'" >&2
        exit 1
        ;;
esac

export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-18
export CMAKE_POLICY_VERSION_MINIMUM=3.5

cargo_nextest="cargo nextest run"
cargo_test="cargo test"
cargo_build="cargo build"

# Use cross-rs for aarch64 cross compile
if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    cargo_nextest="cross test"
    cargo_test="cross test"
    cargo_build="cross build"
fi

# Install the rust toolchain
rustup default $RUST_VERSION
rustup target add --toolchain $RUST_VERSION $TARGET

function common_tests() {
    $cargo_nextest --release --target $TARGET
    $cargo_nextest --features pkcs12_rc2,dsa,ssl --target $TARGET
    $cargo_nextest --test async_session --features=async-rt,ssl,legacy_protocols --target $TARGET
    $cargo_nextest chrono --features=chrono,ssl,x509 --target $TARGET

    # If AES-NI is supported, test the feature
    if [ -n "$AES_NI_SUPPORT" ]; then
        $cargo_nextest --features force_aesni_support --target $TARGET
        $cargo_nextest --features force_aesni_support,x509,ssl --target $TARGET
    fi
    # If zlib is installed, test the zlib feature
    if [ -n "$ZLIB_INSTALLED" ]; then
        $cargo_nextest --features zlib --target $TARGET
        $cargo_nextest --test async_session --features=async-rt,ssl,zlib --target $TARGET
        $cargo_nextest --test async_session --features=async-rt,ssl,zlib,legacy_protocols --target $TARGET
    fi
}

function check_sgx_build() {
    $cargo_test --no-run --target=$TARGET
    $cargo_test --no-run --features ssl --target=$TARGET
}

function no_std_tests() {
    $cargo_nextest --no-default-features --features no_std_deps --target $TARGET
    $cargo_nextest --no-default-features --features no_std_deps,rdrand,time,ssl --target $TARGET
}

if [[ "$TARGET" =~ ^x86_64-pc-windows- ]] && [[ "$MATRIX_OS" =~ ^ubuntu- ]]; then
    export CROSS_TOOLCHAIN_PREFIX=x86_64-w64-mingw32-
    export CROSS_TOOLCHAIN_SUFFIX=-posix
    export CROSS_SYSROOT=/usr/x86_64-w64-mingw32
    export CROSS_TARGET_RUNNER="env -u CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER wine"
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$CROSS_TOOLCHAIN_PREFIX"gcc"$CROSS_TOOLCHAIN_SUFFIX"
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER="$CROSS_TARGET_RUNNER"
    export AR_x86_64_pc_windows_gnu="$CROSS_TOOLCHAIN_PREFIX"ar
    export CC_x86_64_pc_windows_gnu="$CROSS_TOOLCHAIN_PREFIX"gcc"$CROSS_TOOLCHAIN_SUFFIX"
    export CXX_x86_64_pc_windows_gnu="$CROSS_TOOLCHAIN_PREFIX"g++"$CROSS_TOOLCHAIN_SUFFIX"
    export BINDGEN_EXTRA_CLANG_ARGS_x86_64_pc_windows_gnu="--sysroot=$CROSS_SYSROOT -idirafter/usr/include"

    # Initialize the wine prefix (virtual windows installation)
    export WINEPREFIX=/tmp/wine
    mkdir -p "${WINEPREFIX}"
    wineboot &> /dev/null || true

    # Put libstdc++ and some other mingw dlls in WINEPATH
    # This must work for x86_64 and i686
    P1="$(dirname "$(find /usr -name libwinpthread-1.dll)")"

    WINEPATH="$(ls -d /usr/lib/gcc/*-w64-mingw32/*posix);${P1}"
    export WINEPATH
fi

cd "${repo_root}/mbedtls"
case "$TARGET" in
    x86_64-unknown-linux-gnu)
        common_tests
        no_std_tests
        ;;
    x86_64-fortanix-unknown-sgx)
        check_sgx_build
        ;;
    aarch64-unknown-linux-musl)
        common_tests
        ;;
    x86_64-pc-windows-gnu)
        $cargo_build --release --features ssl,dsa,rdrand,force_aesni_support,async-rt --target $TARGET
        common_tests
        no_std_tests
        # special case: mbedtls should compile successfully on windows only with `std` feature
        $cargo_nextest --no-default-features --features std --target $TARGET
        ;;
    x86_64-pc-windows-msvc)
        common_tests
        no_std_tests
        # special case: mbedtls should compile successfully on windows only with `std` feature
        $cargo_nextest --no-default-features --features std --target $TARGET
        ;;
    x86_64-apple-darwin)
        common_tests
        $cargo_nextest --no-default-features --features no_std_deps --target $TARGET
        ;;
    *)
        echo "Error: Unknown or unsupported target: $TARGET" >&2
        exit 1
        ;;
esac
