#!/bin/bash
set -e
cd "$(dirname "$0")"

# This script needs cargo-binstall installed
# Please check: https://github.com/cargo-bins/cargo-binstall

cargo binstall cargo-nextest@0.9.52 --secure
cargo binstall cross@0.2.5 --secure

# Array containing the configurations (rust and target)
# Please comment out other options if you do not want to test them
configs=(
    "stable|x86_64-unknown-linux-gnu"
    "stable|x86_64-fortanix-unknown-sgx"
    "stable|aarch64-unknown-linux-musl"
    "nightly|x86_64-unknown-linux-gnu"
    "beta|x86_64-unknown-linux-gnu"
)

# Path to the script to run
given_script="./ci.sh"

# Iterate over each configuration
for config in "${configs[@]}"; do
    # Split the configuration into rust and target using IFS (Internal Field Separator)
    IFS='|' read -r rust target <<< "$config"
    echo "Running $given_script with RUST_VERSION=$rust and TARGET=$target"
    
    # Export the variables to be used in the given script
    export RUST_VERSION=$rust
    export TARGET=$target
    
    # Run the given script with the set environment variables
    $given_script
    
    echo "Finished running $given_script with RUST_VERSION=$rust and TARGET=$target"
done


