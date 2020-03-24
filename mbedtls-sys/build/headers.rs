/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::have_feature;

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
 *      grep '^#include' *|grep -v '<'|grep -v MBEDTLS_|sed 's/:#include//;s/"//g'|grep -v _alt.h; \
 *      ls *.h|awk '{print $1 " " $1}' \
 *  )|tsort|tac| \
 *  egrep -v '^(compat-1.3.h|certs.h|config.h|check_config.h)$' \
 * )
 */

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const ORDERED: &'static [(Option<&'static str>, &'static str)] = &[
    (None,                 "aes.h"),
    (Some("aesni"),        "aesni.h"),
    (None,                 "arc4.h"),
    (None,                 "aria.h"),
    (None,                 "asn1.h"),
    (None,                 "asn1write.h"),
    (None,                 "base64.h"),
    (None,                 "bignum.h"),
    (None,                 "blowfish.h"),
    (None,                 "bn_mul.h"),
    (None,                 "camellia.h"),
    (None,                 "ccm.h"),
    (None,                 "chacha20.h"),
    (None,                 "chachapoly.h"),
    (None,                 "cipher.h"),
    (None,                 "cipher_internal.h"),
    (None,                 "cmac.h"),
    (None,                 "ctr_drbg.h"),
    (None,                 "debug.h"),
    (None,                 "des.h"),
    (None,                 "dhm.h"),
    (None,                 "ecdh.h"),
    (None,                 "ecdsa.h"),
    (None,                 "ecjpake.h"),
    (None,                 "ecp.h"),
    (None,                 "ecp_internal.h"),
    (None,                 "entropy.h"),
    (None,                 "entropy_poll.h"),
    (None,                 "error.h"),
    (None,                 "gcm.h"),
    (Some("havege"),       "havege.h"),
    (None,                 "hkdf.h"),
    (None,                 "hmac_drbg.h"),
    (None,                 "md2.h"),
    (None,                 "md4.h"),
    (None,                 "md5.h"),
    (None,                 "md.h"),
    (None,                 "md_internal.h"),
    (None,                 "memory_buffer_alloc.h"),
    (None,                 "net.h"),
    (None,                 "net_sockets.h"),
    (None,                 "nist_kw.h"),
    (None,                 "oid.h"),
    (Some("padlock"),      "padlock.h"),
    (None,                 "pem.h"),
    (Some("pkcs11"),       "pkcs11.h"),
    (None,                 "pkcs12.h"),
    (None,                 "pkcs5.h"),
    (None,                 "pk.h"),
    (None,                 "pk_internal.h"),
    (None,                 "platform.h"),
    (None,                 "platform_time.h"),
    (None,                 "platform_util.h"),
    (None,                 "poly1305.h"),
    (None,                 "psa_util.h"),
    (None,                 "ripemd160.h"),
    (None,                 "rsa.h"),
    (None,                 "rsa_internal.h"),
    (None,                 "sha1.h"),
    (None,                 "sha256.h"),
    (None,                 "sha512.h"),
    (None,                 "ssl_cache.h"),
    (None,                 "ssl_ciphersuites.h"),
    (None,                 "ssl_cookie.h"),
    (None,                 "ssl.h"),
    (None,                 "ssl_internal.h"),
    (None,                 "ssl_ticket.h"),
    (Some("threading"),    "threading.h"),
    (None,                 "timing.h"),
    (None,                 "version.h"),
    (None,                 "x509_crl.h"),
    (None,                 "x509_crt.h"),
    (None,                 "x509_csr.h"),
    (None,                 "x509.h"),
    (None,                 "xtea.h"),
];

pub fn enabled_ordered() -> Box<dyn Iterator<Item = &'static str>> {
    Box::new(ORDERED.iter().filter_map(|&(feat, h)| {
        if feat.map(have_feature).unwrap_or(true) {
            Some(h)
        } else {
            None
        }
    }))
}
