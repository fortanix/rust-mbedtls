#!/bin/bash
set -ex
cd "$(dirname "$0")"

# According to `mbedtls-sys/vendor/README.md`, need to install needed pkgs
python3 -m pip install -r ./mbedtls-sys/vendor/scripts/basic.requirements.txt

if [ -z $TRAVIS_RUST_VERSION ]; then
    echo "Expected TRAVIS_RUST_VERSION to be set in env"
    exit 1
fi
export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11
# to be removed after migration to rustc 1.70.., issue #277
export RUSTFLAGS="-A ambiguous_glob_reexports"


# Setup dependencies and tools

# According to `mbedtls-sys/vendor/README.md`, need to install needed pkgs
python3 -m pip install -r ./mbedtls-sys/vendor/scripts/basic.requirements.txt
# function for downloading pre-built `cargo-nextest` on various platform
download_cargo_nextest() {
    local platform="$1"
    local cargo_nextest_hash="$2"
    local url="$3"
    echo "Check if need to download pre-built $platform 'cargo-nextest'"
    if ! echo "${cargo_nextest_hash} ${CARGO_HOME:-$HOME/.cargo}/bin/cargo-nextest" | sha512sum -c; then
        curl -LsSf "$url" | tar zxf - -C "${CARGO_HOME:-$HOME/.cargo}/bin"
        echo "${cargo_nextest_hash} ${CARGO_HOME:-$HOME/.cargo}/bin/cargo-nextest" | sha512sum -c
    fi
}
# download pre-built `cargo-nextest`
platform=$(dpkg --print-architecture)
case "$platform" in
  amd64)
    download_cargo_nextest "amd64" "d22ce5799f3056807fd0cd8223a290c7153a5f084d5ab931fce755c2cabd33f79c0f75542eb724fe07a7ca083f415ec1f84edc46584b06df43d97a0ff91018da" "https://get.nexte.st/0.9.52/linux"
    ;;
  arm64)
    download_cargo_nextest "arm64" "cff3297c84560de8693e7f887fcf6cf33ab0036e27a9debf2b0a0832094555335f34dc30d0f9d1128ce8472dcb4594a3cf33be2357b19dcc94269b58090cc1a9" "https://get.nexte.st/0.9.52/linux-arm"
    ;;
  *)
    echo "Unknown platform"
    ;;
esac


# Test logic start from here
cd "./mbedtls"
if [ "$TRAVIS_RUST_VERSION" == "stable" ] || [ "$TRAVIS_RUST_VERSION" == "beta" ] || [ "$TRAVIS_RUST_VERSION" == "nightly" ]; then
    # Install the rust toolchain
    rustup default $TRAVIS_RUST_VERSION
    rustup target add --toolchain $TRAVIS_RUST_VERSION $TARGET

    # The SGX target cannot be run under test like a ELF binary
    if [ "$TARGET" != "x86_64-fortanix-unknown-sgx" ]; then 
        # make sure that explicitly providing the default target works
        cargo nextest run --target $TARGET --release
        cargo nextest run --features dsa --target $TARGET
        cargo nextest run --features async-rt --test async_session --test hyper_async --target $TARGET
        
        # If AES-NI is supported, test the feature
        if [ -n "$AES_NI_SUPPORT" ]; then
            cargo nextest run --features force_aesni_support --target $TARGET
        fi

        # no_std tests only are able to run on x86 platform
        if [ "$TARGET" == "x86_64-unknown-linux-gnu" ]; then
            cargo nextest run --no-default-features --features no_std_deps,rdrand,time --target $TARGET
            cargo nextest run --no-default-features --features no_std_deps,rdrand --target $TARGET
        fi
    else
        cargo +$TRAVIS_RUST_VERSION test --no-run --target=$TARGET
    fi

else
    echo "Unknown version $TRAVIS_RUST_VERSION"
    exit 1
fi
