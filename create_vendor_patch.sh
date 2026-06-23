#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "This script creates a git-am-compatible patch file from the"
    echo "aggregate diff between master and HEAD under mbedtls-sys/vendor."
    echo
    echo "Usage: $0 <patch-name>"
    echo "Example: $0 Load-less-pointers-to-avoid-LFENCE-instructions"
    exit 1
fi

cd "$(dirname "$0")"

BASE_REF="master"
VENDOR_FOLDER="mbedtls-sys/vendor"
PATCHES_FOLDER="mbedtls-sys/vendor-patches"
PATCH_TITLE=$1

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
    echo "Base ref '$BASE_REF' does not exist."
    exit 1
fi

if git diff --quiet "$BASE_REF"..HEAD -- "$VENDOR_FOLDER"; then
    echo "No committed changes found between '$BASE_REF' and HEAD under '$VENDOR_FOLDER'."
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Warning: uncommitted changes exist and will not be included."
fi

mkdir -p "$PATCHES_FOLDER"

PATCH_NAME=$(printf '%s' "$PATCH_TITLE" | tr '[:space:]' '-' | tr -cd '[:alnum:]._-')
if [ -z "$PATCH_NAME" ]; then
    echo "Patch name is empty after sanitizing."
    exit 1
fi

next_number=1
for patch in "$PATCHES_FOLDER"/[0-9][0-9][0-9][0-9]-*.patch; do
    [ -e "$patch" ] || continue
    number=$(basename "$patch" | cut -d- -f1)
    if [ "$number" -ge "$next_number" ]; then
        next_number=$((number + 1))
    fi
done

PATCH_FILE="$PATCHES_FOLDER/$(printf "%04d" "$next_number")-$PATCH_NAME.patch"

if [ -e "$PATCH_FILE" ]; then
    echo "Patch file already exists: $PATCH_FILE"
    exit 1
fi

{
    echo "From $(git rev-parse HEAD) Mon Sep 17 00:00:00 2001"
    echo "From: $(git show -s --format='%an <%ae>' HEAD)"
    echo "Date: $(git show -s --format='%aD' HEAD)"
    echo "Subject: [PATCH] $PATCH_TITLE"
    echo
    echo "Generated from:"
    echo "  git diff $BASE_REF..HEAD -- $VENDOR_FOLDER"
    echo "---"
    git diff --stat "$BASE_REF"..HEAD -- "$VENDOR_FOLDER"
    echo
    git diff --binary --full-index "$BASE_REF"..HEAD -- "$VENDOR_FOLDER"
} > "$PATCH_FILE"

echo "Created patch file: $PATCH_FILE"
