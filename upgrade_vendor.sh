#!/bin/bash

set -ex

# Check if a tag name is provided
if [ "$#" -ne 1 ]; then
    echo "This script upgrade the vendor mbedtls code to given tag version"
    echo "and apply all patches under mbedtls-sys/vendor_patches folder."
    echo "You may need to resolve patch conflicts if this script failed."
    echo
    echo "Usage: $0 <tag-name or branch-name>"
    exit 1
fi

cd "$(dirname "$0")"

# Get the current Git branch
current_branch=$(git rev-parse --abbrev-ref HEAD)

# Check if the current branch is 'main'
if [ "$current_branch" = "main" ]; then
    echo "Currently on 'main' branch. Please use new branch for upgrading!"
    exit 1
fi

TAG_NAME=$1
REPO_URL="https://github.com/Mbed-TLS/mbedtls"
VENDOR_FOLDER="mbedtls-sys/vendor"
# Step 1: Remove all files under "$VENDOR_FOLDER"
echo "Recreate "$VENDOR_FOLDER" folder to cleanup old vendor code"
rm -rf "$VENDOR_FOLDER"
mkdir -p "$VENDOR_FOLDER"

# Step 2: Clone the repository using the given tag name
echo "Cloning the repository..."
git clone --depth 1 --branch "$TAG_NAME" "$REPO_URL" "$VENDOR_FOLDER"
rm -rf "$VENDOR_FOLDER"/.git

echo "Creating commit for vendor update"
git add "$VENDOR_FOLDER"
git commit -m "Vendor Change: upgrade mbedtls to $TAG_NAME"

# Step 3: Apply patches
PATCHES_FOLDER=""$VENDOR_FOLDER"-patches"
echo "Applying patches under $PATCHES_FOLDER"
git am --3way "$PATCHES_FOLDER"/*

echo "Script completed successfully."
echo "Now you need to update mbedtls-sys crate version number."
