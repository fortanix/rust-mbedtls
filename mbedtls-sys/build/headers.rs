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
    (None,                 "xtea.h"),
    (None,                 "x509_csr.h"),
    (None,                 "x509_crt.h"),
    (None,                 "x509_crl.h"),
    (None,                 "x509.h"),
    (None,                 "version.h"),
    (None,                 "timing.h"),
    (Some("threading"),    "threading.h"),
    (None,                 "ssl_ticket.h"),
    (None,                 "ssl_internal.h"),
    (None,                 "ssl_cookie.h"),
    (None,                 "ssl_ciphersuites.h"),
    (None,                 "ssl_cache.h"),
    (None,                 "ssl.h"),
    (None,                 "sha512.h"),
    (None,                 "sha256.h"),
    (None,                 "sha1.h"),
    (None,                 "rsa_internal.h"),
    (None,                 "rsa.h"),
    (None,                 "ripemd160.h"),
    (None,                 "psa_util.h"),
    (None,                 "poly1305.h"),
    (None,                 "platform_util.h"),
    (None,                 "platform_time.h"),
    (None,                 "platform.h"),
    (None,                 "pkcs5.h"),
    (None,                 "pkcs12.h"),
    (Some("pkcs11"),       "pkcs11.h"),
    (None,                 "pk_internal.h"),
    (None,                 "pk.h"),
    (None,                 "pem.h"),
    (None,                 "padlock.h"),
    (None,                 "oid.h"),
    (None,                 "nist_kw.h"),
    (None,                 "net_sockets.h"),
    (None,                 "net.h"),
    (None,                 "memory_buffer_alloc.h"),
    (None,                 "md_internal.h"),
    (None,                 "md5.h"),
    (None,                 "md4.h"),
    (None,                 "md2.h"),
    (None,                 "md.h"),
    (None,                 "hmac_drbg.h"),
    (None,                 "hkdf.h"),
    (None,                 "havege.h"),
    (None,                 "gcm.h"),
    (None,                 "error.h"),
    (None,                 "entropy_poll.h"),
    (None,                 "entropy.h"),
    (None,                 "ecp_internal.h"),
    (None,                 "ecp.h"),
    (None,                 "ecjpake.h"),
    (None,                 "ecdsa.h"),
    (None,                 "ecdh.h"),
    (None,                 "dhm.h"),
    (None,                 "des.h"),
    (None,                 "debug.h"),
    (None,                 "ctr_drbg.h"),
    (None,                 "cmac.h"),
    (None,                 "cipher_internal.h"),
    (None,                 "cipher.h"),
    (None,                 "chachapoly.h"),
    (None,                 "chacha20.h"),
    (None,                 "ccm.h"),
    (None,                 "camellia.h"),
    (None,                 "bn_mul.h"),
    (None,                 "blowfish.h"),
    (None,                 "bignum.h"),
    (None,                 "base64.h"),
    (None,                 "asn1write.h"),
    (None,                 "asn1.h"),
    (None,                 "aria.h"),
    (None,                 "arc4.h"),
    (None,                 "aesni.h"),
    (None,                 "aes.h"),
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
