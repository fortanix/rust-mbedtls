#!/bin/bash
#
# This is to quickly run unit tests before delivery.
# Output is verbose on purpose, there must be no memory errors before reviews/merges.
#
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --num-callers=100 --track-origins=yes --leak-check=full --track-fds=yes --time-stamp=yes --malloc-fill=fd --free-fill=fd" cargo test --features=default,pthread