#!/bin/bash

set -x
set -euo pipefail


main() {
    local version="10.0.0.0~noble-1"

    dpkg --add-architecture i386

    # add repository for latest wine version and install from source
    # hardcode version, since we might want to avoid a version later.
    wget -nc https://dl.winehq.org/wine-builds/winehq.key

    # Hash check for winehq.key
    echo "d965d646defe94b3dfba6d5b4406900ac6c81065428bf9d9303ad7a72ee8d1b8  winehq.key" | sha256sum -c -

    mkdir -p /etc/apt/keyrings
    mv winehq.key /etc/apt/keyrings/winehq-archive.key

    wget -nc https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources
    # Hash check for winehq-noble.sources
    echo "b5962429ece1f831c9f713c13f9f0d26bb367117ef56706648ff385f004779fb  winehq-noble.sources" | sha256sum -c -

    mv winehq-noble.sources /etc/apt/sources.list.d/

    # winehq requires all the dependencies to be manually specified
    # if we're not using the latest version of a given major version.
    apt-get update
    apt install --no-install-recommends --assume-yes \
        "wine-stable=${version}" \
        "wine-stable-amd64=${version}" \
        "wine-stable-i386=${version}" \
        "winehq-stable=${version}"
}

main "${@}"
