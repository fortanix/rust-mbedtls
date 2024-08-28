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
        Darwin*)
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

aarch64_cross_toolchain_hash=c8ee0e7fd58f5ec6811e3cec5fcdd8fc47cb2b49fb50e9d7717696ddb69c812547b5f389558f62dfbf9db7d6ad808a5a515cc466b8ea3e9ab3daeb20ba1adf33
# save to directory that will be cached
aarch64_cross_toolchain_save_path=${repo_root}/target/aarch64-linux-musl-cross.tgz
mkdir -p ${repo_root}/target
if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    if ! check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}; then
        wget https://more.musl.cc/10-20210301/x86_64-linux-musl/aarch64-linux-musl-cross.tgz -O ${aarch64_cross_toolchain_save_path}
        check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}
    fi
    tar -xf ${aarch64_cross_toolchain_save_path} -C /tmp;
fi

