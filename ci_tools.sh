#!/bin/bash
set -ex
cd "$(dirname "$0")"

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

# Setup dependencies and tools

# checks if a file has a specific sha512 hash
check_sha512() {
    local hash="$1"
    local file="$2"
    local platform=$(uname)
    case $platform in
        Linux)
            sha512sum -c <<< "$hash *$file"
            ;;
        Darwin)
            shasum -a 512 -c <<< "$hash *$file"
            ;;
        MINGW64_NT-*)
            sha512sum -c <<< "$hash *$file"
            ;;
        *)
            echo "Unsupported platform '$platfom'"
            exit 1
            ;;
    esac
}

# function for downloading pre-built `cargo-nextest` on various platforms
download_cargo_nextest() {
    local platform="$1"
    local cargo_nextest_hash="$2"
    local url="$3"
    echo "Check if need to download pre-built $platform 'cargo-nextest'"
    if ! check_sha512 "${cargo_nextest_hash}" "${CARGO_HOME:-$HOME/.cargo}/bin/cargo-nextest"; then
        case $platform in
            MINGW64-*)
                curl -LsSf "$url" -o temp.zip && unzip -d "${CARGO_HOME:-$HOME/.cargo}/bin" temp.zip && rm temp.zip
                ;;
            *)
                curl -LsSf "$url" | tar zxf - -C "${CARGO_HOME:-$HOME/.cargo}/bin"
                ;;
        esac
        check_sha512 "${cargo_nextest_hash}" "${CARGO_HOME:-$HOME/.cargo}/bin/cargo-nextest"
    fi
}

aarch64_cross_toolchain_hash=c8ee0e7fd58f5ec6811e3cec5fcdd8fc47cb2b49fb50e9d7717696ddb69c812547b5f389558f62dfbf9db7d6ad808a5a515cc466b8ea3e9ab3daeb20ba1adf33
# save to directory that will be cached
aarch64_cross_toolchain_save_path=${repo_root}/target/aarch64-linux-musl-cross.tgz
if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    if ! check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}; then
        wget https://more.musl.cc/10-20210301/x86_64-linux-musl/aarch64-linux-musl-cross.tgz -O ${aarch64_cross_toolchain_save_path}
        check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}
    fi
    tar -xf ${aarch64_cross_toolchain_save_path} -C /tmp;
fi

# download pre-built `cargo-nextest`
kernel=$(uname)
architecture=$(uname -m)
case "$kernel-$architecture" in
  Linux-x86_64 | Linux-amd64)
    download_cargo_nextest "amd64" "d22ce5799f3056807fd0cd8223a290c7153a5f084d5ab931fce755c2cabd33f79c0f75542eb724fe07a7ca083f415ec1f84edc46584b06df43d97a0ff91018da" "https://get.nexte.st/0.9.52/linux"
    ;;
  Linux-arm64)
    download_cargo_nextest "arm64" "cff3297c84560de8693e7f887fcf6cf33ab0036e27a9debf2b0a0832094555335f34dc30d0f9d1128ce8472dcb4594a3cf33be2357b19dcc94269b58090cc1a9" "https://get.nexte.st/0.9.52/linux-arm"
    ;;
  Darwin-x86_64)
    download_cargo_nextest "Darwin-amd64" "0bb8b77ce019de3d06ee6b7382d830ed67309f187781e0de3866a0635879b494c7db48d55eee7553cfaa0bfca59abd8f8540a6d81ed703f06f9c81514d20073d" "https://get.nexte.st/0.9.52/mac"
    ;;
  MINGW64_NT-*-x86_64)
    download_cargo_nextest "MINGW64-amd64" "3ffd504a4ef0b4b5e988457e6c525e62bd030d46b8f303f1c4e83a9a8ba89aef34bb239e23f391d1dddb75bea6ff074499153b2c71b06338a05d74916408de9c" "https://get.nexte.st/0.9.52/windows"
    ;;
  *)
    echo "Unknown platform '$kernel-$architecture'"
    exit 1
    ;;
esac
