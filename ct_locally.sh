#!/bin/bash
set -ex

cwd=`pwd`
export script_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

export RUST_BACKTRACE=1
export TRAVIS_HOME=$HOME

targets=()
targets+=("x86_64-unknown-linux-gnu")
targets+=("aarch64-unknown-linux-musl")
targets+=("x86_64-fortanix-unknown-sgx")

versions=()
versions+=("beta")
versions+=("nightly")

aarch64_cross_toolchain_hash=c8ee0e7fd58f5ec6811e3cec5fcdd8fc47cb2b49fb50e9d7717696ddb69c812547b5f389558f62dfbf9db7d6ad808a5a515cc466b8ea3e9ab3daeb20ba1adf33
# save to directorie that will be cached
aarch64_cross_toolchain_save_path=$TRAVIS_HOME/.rustup/aarch64-linux-musl-cross.tgz
if [ "$TARGET" == "aarch64-unknown-linux-musl" ]; then
    if ! echo "${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}" | sha512sum -c; then
        wget https://more.musl.cc/10-20210301/x86_64-linux-musl/aarch64-linux-musl-cross.tgz -O ${aarch64_cross_toolchain_save_path}
        echo "${aarch64_cross_toolchain_hash} ${aarch64_cross_toolchain_save_path}" | sha512sum -c
    fi
    tar -xf ${aarch64_cross_toolchain_save_path} -C /tmp;
fi

export CC_aarch64_unknown_linux_musl=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64


for local_target in "${targets[@]}"
do
    export TARGET=$local_target
    export TRAVIS_RUST_VERSION="stable"
    $script_dir/ct.sh
done


for local_version in "${versions[@]}"
do
    export TARGET="x86_64-unknown-linux-gnu"
    export AES_NI_SUPPORT=true
    export ZLIB_INSTALLED=true
    export TRAVIS_RUST_VERSION=$local_version
    $script_dir/ct.sh
done

cd $cwd