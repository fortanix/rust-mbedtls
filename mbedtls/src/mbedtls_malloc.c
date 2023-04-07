/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// Follow same pattern for config and alloc/free as everywhere in mbedtls
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

// Use several macros to get the preprocessor to actually replace RUST_MBEDTLS_METADATA_HASH
#define append_macro_inner(a, b) a##_##b
#define append_macro(a, b) append_macro_inner(a, b)
#define APPEND_METADATA_HASH(f) append_macro(f, RUST_MBEDTLS_METADATA_HASH)

extern void *APPEND_METADATA_HASH(forward_mbedtls_calloc)( size_t n, size_t size ) {
    return mbedtls_calloc(n, size);
}

extern void APPEND_METADATA_HASH(forward_mbedtls_free)( void *ptr ) {
    mbedtls_free(ptr);
}
