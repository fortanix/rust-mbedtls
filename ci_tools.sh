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

aarch64_cross_toolchain_hash=8695ff86979cdf30fbbcd33061711f5b1ebc3c48a87822b9ca56cde6d3a22abd4dab30fdcd1789ac27c6febbaeb9e5bde59d79d66552fae53d54cc1377a19272
# save to directory that will be cached
aarch64_cross_toolchain_save_path=${repo_root}/target/aarch64-linux-musl-cross.tgz
mkdir -p ${repo_root}/target
if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    if ! check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}; then
        wget --tries=3 --timeout=5 --waitretry=5 --retry-connrefused https://musl.cc/aarch64-linux-musl-cross.tgz -O ${aarch64_cross_toolchain_save_path}
        check_sha512 ${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}
    fi
    tar -xf ${aarch64_cross_toolchain_save_path} -C /tmp;
fi

