/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::features::FEATURES;

/* This list has been generated from a include/mbedtls/ directory as follows:
 *
 * 1. Find all occurences of #include "", but skip MBEDTLS macros and *_alt.h
 * 2. Add a list all files in the current directory
 * 3. Reverse topological sort
 * 4. Exclude certain files
 * 5. Show only files that exist in cmdline order
 *
 * ls -f1 $( \
 *  ( \
 *      grep '^#include' *|grep -v '<'|grep -v MBEDTLS_|sed 's/:#include//;s/"//g'|sed 's#mbedtls/##g'| egrep -v ' (psa/crypto.h|psa/crypto_config.h|everest/everest.h|zlib.h|.*_alt.h)$'; \
 *       ls *.h|awk '{print $1 " " $1}' \
 *  )|tsort|tac| \
 *  egrep -v '^(compat-2.x.h|mbedtls_config.h|check_config.h)$' \
 * )
 */

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const ORDERED: &'static [(Option<&'static str>, &'static str)] = &[
    (None,                 "config_psa.h"),
    (None,                 "platform_time.h"),
    (None,                 "platform_util.h"),
    (None,                 "bignum.h"),
    (None,                 "md.h"),
    (Some("threading"),    "threading.h"),
    (None,                 "ecp.h"),
    (None,                 "rsa.h"),
    (None,                 "ecdsa.h"),
    (None,                 "asn1.h"),
    (None,                 "pk.h"),
    (None,                 "x509.h"),
    (None,                 "cipher.h"),
    (None,                 "x509_crl.h"),
    (None,                 "aes.h"),
    (None,                 "ssl_ciphersuites.h"),
    (None,                 "x509_crt.h"),
    (None,                 "dhm.h"),
    (None,                 "ecdh.h"),
    (None,                 "oid.h"),
    (None,                 "ctr_drbg.h"),
    (None,                 "hmac_drbg.h"),
    (None,                 "ssl.h"),
    (None,                 "md5.h"),
    (None,                 "sha1.h"),
    (None,                 "sha256.h"),
    (None,                 "sha512.h"),
    (None,                 "ecjpake.h"),
    (None,                 "psa_util.h"),
    (None,                 "net_sockets.h"),
    (None,                 "poly1305.h"),
    (None,                 "chacha20.h"),
    (None,                 "x509_csr.h"),
    (None,                 "build_info.h"),
    (None,                 "timing.h"),
    (None,                 "ssl_ticket.h"),
    (None,                 "ssl_cookie.h"),
    (None,                 "ssl_cache.h"),
    (None,                 "ripemd160.h"),
    (None,                 "platform.h"),
    (None,                 "pkcs5.h"),
    (None,                 "pkcs12.h"),
    (None,                 "pem.h"),
    (None,                 "nist_kw.h"),
    (None,                 "memory_buffer_alloc.h"),
    (None,                 "hkdf.h"),
    (None,                 "gcm.h"),
    (None,                 "error.h"),
    (None,                 "entropy.h"),
    (None,                 "des.h"),
    (None,                 "debug.h"),
    (None,                 "constant_time.h"),
    (None,                 "cmac.h"),
    (None,                 "chachapoly.h"),
    (None,                 "ccm.h"),
    (None,                 "camellia.h"),
    (None,                 "base64.h"),
    (None,                 "asn1write.h"),
    (None,                 "aria.h"),
];

pub fn enabled_ordered() -> Box<dyn Iterator<Item = &'static str>> {
    Box::new(ORDERED.iter().filter_map(|&(feat, h)| {
        if feat.map_or(true, |feat| FEATURES.have_feature(feat)) {
            Some(h)
        } else {
            None
        }
    }))
}
