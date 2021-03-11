/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::collections::HashMap;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Macro {
    Undefined,
    Defined,
    #[allow(dead_code)]
    DefinedAs(&'static str),
}
use self::Macro::*;

impl Macro {
    pub fn define(self, name: &'static str) -> String {
        match self {
            Undefined => String::new(),
            Defined => format!("#define {}\n", name),
            DefinedAs(v) => format!("#define {} {}\n", name, v),
        }
    }
}

pub type CDefine = (&'static str, Macro);

pub const PREFIX: &'static str = r#"
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
"#;

/*

DEFAULT_DEFINES was generated using the following script

#!/usr/bin/python

import re

simple_define = re.compile(r'(.*)#define (MBEDTLS_[A-Z0-9_]+)$')
define_with_default = re.compile(r'.*#define (MBEDTLS_[A-Z0-9_]+) +([0-9A-Za-z_]+)')

def format(macro, state):
    return "    (\"%s\", %s)," % (macro, state.rjust(49 - len(macro) + len(state)))

for line in open('vendor/include/mbedtls/config.h').readlines():
    match = simple_define.match(line)

    if match:
        state = "Undefined" if match.group(1).strip() == '//' else "Defined"
        print format(match.group(2), state)
    else:
        match = define_with_default.match(line)
        if match:
            print format(match.group(1), "Undefined") + (" // default: %s" % (match.group(2)))
*/

#[cfg_attr(rustfmt, rustfmt_skip)]
const DEFAULT_DEFINES: &'static [CDefine] = &[
    ("MBEDTLS_HAVE_ASM",                                  Defined),
    ("MBEDTLS_NO_UDBL_DIVISION",                          Undefined),
    ("MBEDTLS_NO_64BIT_MULTIPLICATION",                   Undefined),
    ("MBEDTLS_HAVE_SSE2",                                 Undefined),
    ("MBEDTLS_HAVE_TIME",                                 Undefined),
    ("MBEDTLS_HAVE_TIME_DATE",                            Undefined),
    ("MBEDTLS_PLATFORM_MEMORY",                           Undefined),
    ("MBEDTLS_PLATFORM_NO_STD_FUNCTIONS",                 Undefined),
    ("MBEDTLS_PLATFORM_EXIT_ALT",                         Undefined),
    ("MBEDTLS_PLATFORM_TIME_ALT",                         Undefined),
    ("MBEDTLS_PLATFORM_FPRINTF_ALT",                      Undefined),
    ("MBEDTLS_PLATFORM_PRINTF_ALT",                       Undefined),
    ("MBEDTLS_PLATFORM_SNPRINTF_ALT",                     Undefined),
    ("MBEDTLS_PLATFORM_VSNPRINTF_ALT",                    Undefined),
    ("MBEDTLS_PLATFORM_NV_SEED_ALT",                      Undefined),
    ("MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT",               Undefined),
    ("MBEDTLS_DEPRECATED_WARNING",                        Undefined),
    ("MBEDTLS_DEPRECATED_REMOVED",                        Undefined),
    ("MBEDTLS_CHECK_PARAMS",                              Undefined),
    ("MBEDTLS_CHECK_PARAMS_ASSERT",                       Undefined),
    ("MBEDTLS_TIMING_ALT",                                Undefined),
    ("MBEDTLS_AES_ALT",                                   Undefined),
    ("MBEDTLS_ARC4_ALT",                                  Undefined),
    ("MBEDTLS_ARIA_ALT",                                  Undefined),
    ("MBEDTLS_BLOWFISH_ALT",                              Undefined),
    ("MBEDTLS_CAMELLIA_ALT",                              Undefined),
    ("MBEDTLS_CCM_ALT",                                   Undefined),
    ("MBEDTLS_CHACHA20_ALT",                              Undefined),
    ("MBEDTLS_CHACHAPOLY_ALT",                            Undefined),
    ("MBEDTLS_CMAC_ALT",                                  Undefined),
    ("MBEDTLS_DES_ALT",                                   Undefined),
    ("MBEDTLS_DHM_ALT",                                   Undefined),
    ("MBEDTLS_ECJPAKE_ALT",                               Undefined),
    ("MBEDTLS_GCM_ALT",                                   Undefined),
    ("MBEDTLS_NIST_KW_ALT",                               Undefined),
    ("MBEDTLS_MD2_ALT",                                   Undefined),
    ("MBEDTLS_MD4_ALT",                                   Undefined),
    ("MBEDTLS_MD5_ALT",                                   Undefined),
    ("MBEDTLS_POLY1305_ALT",                              Undefined),
    ("MBEDTLS_RIPEMD160_ALT",                             Undefined),
    ("MBEDTLS_RSA_ALT",                                   Undefined),
    ("MBEDTLS_SHA1_ALT",                                  Undefined),
    ("MBEDTLS_SHA256_ALT",                                Undefined),
    ("MBEDTLS_SHA512_ALT",                                Undefined),
    ("MBEDTLS_XTEA_ALT",                                  Undefined),
    ("MBEDTLS_ECP_ALT",                                   Undefined),
    ("MBEDTLS_MD2_PROCESS_ALT",                           Undefined),
    ("MBEDTLS_MD4_PROCESS_ALT",                           Undefined),
    ("MBEDTLS_MD5_PROCESS_ALT",                           Undefined),
    ("MBEDTLS_RIPEMD160_PROCESS_ALT",                     Undefined),
    ("MBEDTLS_SHA1_PROCESS_ALT",                          Undefined),
    ("MBEDTLS_SHA256_PROCESS_ALT",                        Undefined),
    ("MBEDTLS_SHA512_PROCESS_ALT",                        Undefined),
    ("MBEDTLS_DES_SETKEY_ALT",                            Undefined),
    ("MBEDTLS_DES_CRYPT_ECB_ALT",                         Undefined),
    ("MBEDTLS_DES3_CRYPT_ECB_ALT",                        Undefined),
    ("MBEDTLS_AES_SETKEY_ENC_ALT",                        Undefined),
    ("MBEDTLS_AES_SETKEY_DEC_ALT",                        Undefined),
    ("MBEDTLS_AES_ENCRYPT_ALT",                           Undefined),
    ("MBEDTLS_AES_DECRYPT_ALT",                           Undefined),
    ("MBEDTLS_ECDH_GEN_PUBLIC_ALT",                       Undefined),
    ("MBEDTLS_ECDH_COMPUTE_SHARED_ALT",                   Undefined),
    ("MBEDTLS_ECDSA_VERIFY_ALT",                          Undefined),
    ("MBEDTLS_ECDSA_SIGN_ALT",                            Undefined),
    ("MBEDTLS_ECDSA_GENKEY_ALT",                          Undefined),
    ("MBEDTLS_ECP_INTERNAL_ALT",                          Undefined),
    ("MBEDTLS_ECP_RANDOMIZE_JAC_ALT",                     Undefined),
    ("MBEDTLS_ECP_ADD_MIXED_ALT",                         Undefined),
    ("MBEDTLS_ECP_DOUBLE_JAC_ALT",                        Undefined),
    ("MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT",                Undefined),
    ("MBEDTLS_ECP_NORMALIZE_JAC_ALT",                     Undefined),
    ("MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT",                    Undefined),
    ("MBEDTLS_ECP_RANDOMIZE_MXZ_ALT",                     Undefined),
    ("MBEDTLS_ECP_NORMALIZE_MXZ_ALT",                     Undefined),
    ("MBEDTLS_TEST_NULL_ENTROPY",                         Undefined),
    ("MBEDTLS_ENTROPY_HARDWARE_ALT",                      Undefined),
    ("MBEDTLS_AES_ROM_TABLES",                            Undefined),
    ("MBEDTLS_AES_FEWER_TABLES",                          Undefined),
    ("MBEDTLS_CAMELLIA_SMALL_MEMORY",                     Undefined),
    ("MBEDTLS_CIPHER_MODE_CBC",                           Defined),
    ("MBEDTLS_CIPHER_MODE_CFB",                           Defined),
    ("MBEDTLS_CIPHER_MODE_CTR",                           Defined),
    ("MBEDTLS_CIPHER_MODE_OFB",                           Defined),
    ("MBEDTLS_CIPHER_MODE_XTS",                           Defined),
    ("MBEDTLS_CIPHER_NULL_CIPHER",                        Undefined),
    ("MBEDTLS_CIPHER_PADDING_PKCS7",                      Defined),
    ("MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS",              Defined),
    ("MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN",              Defined),
    ("MBEDTLS_CIPHER_PADDING_ZEROS",                      Defined),
    ("MBEDTLS_CTR_DRBG_USE_128_BIT_KEY",                  Undefined),
    ("MBEDTLS_ENABLE_WEAK_CIPHERSUITES",                  Undefined),
    ("MBEDTLS_REMOVE_ARC4_CIPHERSUITES",                  Defined),
    ("MBEDTLS_REMOVE_3DES_CIPHERSUITES",                  Defined),
    ("MBEDTLS_ECP_DP_SECP192R1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP224R1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP256R1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP384R1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP521R1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP192K1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP224K1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_SECP256K1_ENABLED",                  Defined),
    ("MBEDTLS_ECP_DP_BP256R1_ENABLED",                    Defined),
    ("MBEDTLS_ECP_DP_BP384R1_ENABLED",                    Defined),
    ("MBEDTLS_ECP_DP_BP512R1_ENABLED",                    Defined),
    ("MBEDTLS_ECP_DP_CURVE25519_ENABLED",                 Defined),
    ("MBEDTLS_ECP_DP_CURVE448_ENABLED",                   Defined),
    ("MBEDTLS_ECP_NIST_OPTIM",                            Defined),
    ("MBEDTLS_ECP_NO_INTERNAL_RNG",                       Undefined),
    ("MBEDTLS_ECP_RESTARTABLE",                           Undefined),
    ("MBEDTLS_ECDH_LEGACY_CONTEXT",                       Defined),
    ("MBEDTLS_ECDSA_DETERMINISTIC",                       Undefined),
    ("MBEDTLS_KEY_EXCHANGE_PSK_ENABLED",                  Defined),
    ("MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED",              Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED",            Defined),
    ("MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED",              Defined),
    ("MBEDTLS_KEY_EXCHANGE_RSA_ENABLED",                  Defined),
    ("MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED",              Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED",            Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED",          Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED",           Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED",             Defined),
    ("MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED",              Undefined),
    ("MBEDTLS_PK_PARSE_EC_EXTENDED",                      Defined),
    ("MBEDTLS_ERROR_STRERROR_DUMMY",                      Defined),
    ("MBEDTLS_GENPRIME",                                  Defined),
    ("MBEDTLS_FS_IO",                                     Undefined),
    ("MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES",                Undefined),
    ("MBEDTLS_NO_PLATFORM_ENTROPY",                       Defined),
    ("MBEDTLS_ENTROPY_FORCE_SHA256",                      Undefined),
    ("MBEDTLS_ENTROPY_NV_SEED",                           Undefined),
    ("MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER",           Undefined),
    ("MBEDTLS_MEMORY_DEBUG",                              Undefined),
    ("MBEDTLS_MEMORY_BACKTRACE",                          Undefined),
    ("MBEDTLS_PK_RSA_ALT_SUPPORT",                        Defined),
    ("MBEDTLS_PKCS1_V15",                                 Defined),
    ("MBEDTLS_PKCS1_V21",                                 Defined),
    ("MBEDTLS_PSA_CRYPTO_DRIVERS",                        Undefined),
    ("MBEDTLS_PSA_CRYPTO_SPM",                            Undefined),
    ("MBEDTLS_PSA_INJECT_ENTROPY",                        Undefined),
    ("MBEDTLS_RSA_NO_CRT",                                Undefined),
    ("MBEDTLS_SELF_TEST",                                 Defined),
    ("MBEDTLS_SHA256_SMALLER",                            Undefined),
    ("MBEDTLS_SHA512_SMALLER",                            Undefined),
    ("MBEDTLS_SHA512_NO_SHA384",                          Undefined),
    ("MBEDTLS_SSL_ALL_ALERT_MESSAGES",                    Defined),
    ("MBEDTLS_SSL_RECORD_CHECKING",                       Defined),
    ("MBEDTLS_SSL_DTLS_CONNECTION_ID",                    Undefined),
    ("MBEDTLS_SSL_ASYNC_PRIVATE",                         Undefined),
    ("MBEDTLS_SSL_CONTEXT_SERIALIZATION",                 Defined),
    ("MBEDTLS_SSL_DEBUG_ALL",                             Undefined),
    ("MBEDTLS_SSL_ENCRYPT_THEN_MAC",                      Defined),
    ("MBEDTLS_SSL_EXTENDED_MASTER_SECRET",                Defined),
    ("MBEDTLS_SSL_FALLBACK_SCSV",                         Defined),
    ("MBEDTLS_SSL_KEEP_PEER_CERTIFICATE",                 Defined),
    ("MBEDTLS_SSL_HW_RECORD_ACCEL",                       Undefined),
    ("MBEDTLS_SSL_CBC_RECORD_SPLITTING",                  Undefined),
    ("MBEDTLS_SSL_RENEGOTIATION",                         Defined),
    ("MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO",        Undefined),
    ("MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE",         Undefined),
    ("MBEDTLS_SSL_MAX_FRAGMENT_LENGTH",                   Defined),
    ("MBEDTLS_SSL_PROTO_SSL3",                            Undefined),
    ("MBEDTLS_SSL_PROTO_TLS1",                            Undefined),
    ("MBEDTLS_SSL_PROTO_TLS1_1",                          Undefined),
    ("MBEDTLS_SSL_PROTO_TLS1_2",                          Defined),
    ("MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL",             Undefined),
    ("MBEDTLS_SSL_PROTO_DTLS",                            Defined),
    ("MBEDTLS_SSL_ALPN",                                  Defined),
    ("MBEDTLS_SSL_DTLS_ANTI_REPLAY",                      Defined),
    ("MBEDTLS_SSL_DTLS_HELLO_VERIFY",                     Defined),
    ("MBEDTLS_SSL_DTLS_SRTP",                             Undefined),
    ("MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE",                Defined),
    ("MBEDTLS_SSL_DTLS_BADMAC_LIMIT",                     Defined),
    ("MBEDTLS_SSL_SESSION_TICKETS",                       Defined),
    ("MBEDTLS_SSL_EXPORT_KEYS",                           Defined),
    ("MBEDTLS_SSL_SERVER_NAME_INDICATION",                Defined),
    ("MBEDTLS_SSL_TRUNCATED_HMAC",                        Defined),
    ("MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT",                 Undefined),
    ("MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH",                Undefined),
    ("MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN",                 Undefined),
    ("MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND",               Undefined),
    ("MBEDTLS_TEST_HOOKS",                                Undefined),
    ("MBEDTLS_THREADING_ALT",                             Undefined),
    ("MBEDTLS_THREADING_PTHREAD",                         Undefined),
    ("MBEDTLS_USE_PSA_CRYPTO",                            Undefined),
    ("MBEDTLS_PSA_CRYPTO_CONFIG",                         Undefined),
    ("MBEDTLS_VERSION_FEATURES",                          Defined),
    ("MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3",              Undefined),
    ("MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION", Undefined),
    ("MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK",         Undefined),
    ("MBEDTLS_X509_CHECK_KEY_USAGE",                      Defined),
    ("MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE",             Defined),
    ("MBEDTLS_X509_RSASSA_PSS_SUPPORT",                   Defined),
    ("MBEDTLS_ZLIB_SUPPORT",                              Undefined),
    ("MBEDTLS_AESNI_C",                                   Undefined),
    ("MBEDTLS_AES_C",                                     Defined),
    ("MBEDTLS_ARC4_C",                                    Defined),
    ("MBEDTLS_ASN1_PARSE_C",                              Defined),
    ("MBEDTLS_ASN1_WRITE_C",                              Defined),
    ("MBEDTLS_BASE64_C",                                  Defined),
    ("MBEDTLS_BIGNUM_C",                                  Defined),
    ("MBEDTLS_BLOWFISH_C",                                Defined),
    ("MBEDTLS_CAMELLIA_C",                                Defined),
    ("MBEDTLS_ARIA_C",                                    Undefined),
    ("MBEDTLS_CCM_C",                                     Defined),
    ("MBEDTLS_CERTS_C",                                   Defined),
    ("MBEDTLS_CHACHA20_C",                                Defined),
    ("MBEDTLS_CHACHAPOLY_C",                              Defined),
    ("MBEDTLS_CIPHER_C",                                  Defined),
    ("MBEDTLS_CMAC_C",                                    Defined),
    ("MBEDTLS_CTR_DRBG_C",                                Defined),
    ("MBEDTLS_DEBUG_C",                                   Undefined),
    ("MBEDTLS_DES_C",                                     Defined),
    ("MBEDTLS_DHM_C",                                     Defined),
    ("MBEDTLS_ECDH_C",                                    Defined),
    ("MBEDTLS_ECDSA_C",                                   Defined),
    ("MBEDTLS_ECJPAKE_C",                                 Defined),
    ("MBEDTLS_ECP_C",                                     Defined),
    ("MBEDTLS_ENTROPY_C",                                 Undefined),
    ("MBEDTLS_ERROR_C",                                   Defined),
    ("MBEDTLS_GCM_C",                                     Defined),
    ("MBEDTLS_HAVEGE_C",                                  Undefined),
    ("MBEDTLS_HKDF_C",                                    Defined),
    ("MBEDTLS_HMAC_DRBG_C",                               Defined),
    ("MBEDTLS_NIST_KW_C",                                 Defined),
    ("MBEDTLS_MD_C",                                      Defined),
    ("MBEDTLS_MD2_C",                                     Defined),
    ("MBEDTLS_MD4_C",                                     Defined),
    ("MBEDTLS_MD5_C",                                     Defined),
    ("MBEDTLS_MEMORY_BUFFER_ALLOC_C",                     Undefined),
    ("MBEDTLS_NET_C",                                     Undefined),
    ("MBEDTLS_OID_C",                                     Defined),
    ("MBEDTLS_PADLOCK_C",                                 Undefined),
    ("MBEDTLS_PEM_PARSE_C",                               Defined),
    ("MBEDTLS_PEM_WRITE_C",                               Defined),
    ("MBEDTLS_PK_C",                                      Defined),
    ("MBEDTLS_PK_PARSE_C",                                Defined),
    ("MBEDTLS_PK_WRITE_C",                                Defined),
    ("MBEDTLS_PKCS5_C",                                   Defined),
    ("MBEDTLS_PKCS11_C",                                  Undefined),
    ("MBEDTLS_PKCS12_C",                                  Defined),
    ("MBEDTLS_PLATFORM_C",                                Undefined),
    ("MBEDTLS_POLY1305_C",                                Defined),
    ("MBEDTLS_PSA_CRYPTO_C",                              Undefined),
    ("MBEDTLS_PSA_CRYPTO_SE_C",                           Undefined),
    ("MBEDTLS_PSA_CRYPTO_STORAGE_C",                      Undefined),
    ("MBEDTLS_PSA_ITS_FILE_C",                            Undefined),
    ("MBEDTLS_RIPEMD160_C",                               Defined),
    ("MBEDTLS_RSA_C",                                     Defined),
    ("MBEDTLS_SHA1_C",                                    Defined),
    ("MBEDTLS_SHA256_C",                                  Defined),
    ("MBEDTLS_SHA512_C",                                  Defined),
    ("MBEDTLS_SSL_CACHE_C",                               Defined),
    ("MBEDTLS_SSL_COOKIE_C",                              Defined),
    ("MBEDTLS_SSL_TICKET_C",                              Defined),
    ("MBEDTLS_SSL_CLI_C",                                 Defined),
    ("MBEDTLS_SSL_SRV_C",                                 Defined),
    ("MBEDTLS_SSL_TLS_C",                                 Defined),
    ("MBEDTLS_THREADING_C",                               Undefined),
    ("MBEDTLS_TIMING_C",                                  Undefined),
    ("MBEDTLS_VERSION_C",                                 Defined),
    ("MBEDTLS_X509_USE_C",                                Defined),
    ("MBEDTLS_X509_CRT_PARSE_C",                          Defined),
    ("MBEDTLS_X509_CRL_PARSE_C",                          Defined),
    ("MBEDTLS_X509_CSR_PARSE_C",                          Defined),
    ("MBEDTLS_X509_CREATE_C",                             Defined),
    ("MBEDTLS_X509_CRT_WRITE_C",                          Defined),
    ("MBEDTLS_X509_CSR_WRITE_C",                          Defined),
    ("MBEDTLS_XTEA_C",                                    Defined),
    ("MBEDTLS_MPI_WINDOW_SIZE",                           Undefined), // default: 6
    ("MBEDTLS_MPI_MAX_SIZE",                              Undefined), // default: 1024
    ("MBEDTLS_CTR_DRBG_ENTROPY_LEN",                      Undefined), // default: 48
    ("MBEDTLS_CTR_DRBG_RESEED_INTERVAL",                  Undefined), // default: 10000
    ("MBEDTLS_CTR_DRBG_MAX_INPUT",                        Undefined), // default: 256
    ("MBEDTLS_CTR_DRBG_MAX_REQUEST",                      Undefined), // default: 1024
    ("MBEDTLS_CTR_DRBG_MAX_SEED_INPUT",                   Undefined), // default: 384
    ("MBEDTLS_HMAC_DRBG_RESEED_INTERVAL",                 Undefined), // default: 10000
    ("MBEDTLS_HMAC_DRBG_MAX_INPUT",                       Undefined), // default: 256
    ("MBEDTLS_HMAC_DRBG_MAX_REQUEST",                     Undefined), // default: 1024
    ("MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT",                  Undefined), // default: 384
    ("MBEDTLS_ECP_MAX_BITS",                              Undefined), // default: 521
    ("MBEDTLS_ECP_WINDOW_SIZE",                           Undefined), // default: 6
    ("MBEDTLS_ECP_FIXED_POINT_OPTIM",                     Undefined), // default: 1
    ("MBEDTLS_ENTROPY_MAX_SOURCES",                       Undefined), // default: 20
    ("MBEDTLS_ENTROPY_MAX_GATHER",                        Undefined), // default: 128
    ("MBEDTLS_ENTROPY_MIN_HARDWARE",                      Undefined), // default: 32
    ("MBEDTLS_MEMORY_ALIGN_MULTIPLE",                     Undefined), // default: 4
    ("MBEDTLS_PLATFORM_STD_CALLOC",                       Undefined), // default: calloc
    ("MBEDTLS_PLATFORM_STD_FREE",                         Undefined), // default: free
    ("MBEDTLS_PLATFORM_STD_EXIT",                         Undefined), // default: exit
    ("MBEDTLS_PLATFORM_STD_TIME",                         Undefined), // default: time
    ("MBEDTLS_PLATFORM_STD_FPRINTF",                      Undefined), // default: fprintf
    ("MBEDTLS_PLATFORM_STD_PRINTF",                       Undefined), // default: printf
    ("MBEDTLS_PLATFORM_STD_SNPRINTF",                     Undefined), // default: snprintf
    ("MBEDTLS_PLATFORM_STD_EXIT_SUCCESS",                 Undefined), // default: 0
    ("MBEDTLS_PLATFORM_STD_EXIT_FAILURE",                 Undefined), // default: 1
    ("MBEDTLS_PLATFORM_STD_NV_SEED_READ",                 Undefined), // default: mbedtls_platform_std_nv_seed_read
    ("MBEDTLS_PLATFORM_STD_NV_SEED_WRITE",                Undefined), // default: mbedtls_platform_std_nv_seed_write
    ("MBEDTLS_PLATFORM_CALLOC_MACRO",                     Undefined), // default: calloc
    ("MBEDTLS_PLATFORM_FREE_MACRO",                       Undefined), // default: free
    ("MBEDTLS_PLATFORM_EXIT_MACRO",                       Undefined), // default: exit
    ("MBEDTLS_PLATFORM_TIME_MACRO",                       Undefined), // default: time
    ("MBEDTLS_PLATFORM_TIME_TYPE_MACRO",                  Undefined), // default: time_t
    ("MBEDTLS_PLATFORM_FPRINTF_MACRO",                    Undefined), // default: fprintf
    ("MBEDTLS_PLATFORM_PRINTF_MACRO",                     Undefined), // default: printf
    ("MBEDTLS_PLATFORM_SNPRINTF_MACRO",                   Undefined), // default: snprintf
    ("MBEDTLS_PLATFORM_VSNPRINTF_MACRO",                  Undefined), // default: vsnprintf
    ("MBEDTLS_PLATFORM_NV_SEED_READ_MACRO",               Undefined), // default: mbedtls_platform_std_nv_seed_read
    ("MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO",              Undefined), // default: mbedtls_platform_std_nv_seed_write
    ("MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT",                 Undefined), // default: 86400
    ("MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES",             Undefined), // default: 50
    ("MBEDTLS_SSL_MAX_CONTENT_LEN",                       Undefined), // default: 16384
    ("MBEDTLS_SSL_IN_CONTENT_LEN",                        Undefined), // default: 16384
    ("MBEDTLS_SSL_CID_IN_LEN_MAX",                        Undefined), // default: 32
    ("MBEDTLS_SSL_CID_OUT_LEN_MAX",                       Undefined), // default: 32
    ("MBEDTLS_SSL_CID_PADDING_GRANULARITY",               Undefined), // default: 16
    ("MBEDTLS_SSL_TLS1_3_PADDING_GRANULARITY",            Undefined), // default: 1
    ("MBEDTLS_SSL_OUT_CONTENT_LEN",                       Undefined), // default: 16384
    ("MBEDTLS_SSL_DTLS_MAX_BUFFERING",                    Undefined), // default: 32768
    ("MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME",               Undefined), // default: 86400
    ("MBEDTLS_PSK_MAX_LEN",                               Undefined), // default: 32
    ("MBEDTLS_SSL_COOKIE_TIMEOUT",                        Undefined), // default: 60
    ("MBEDTLS_SSL_CIPHERSUITES",                          Undefined), // default: no default
    ("MBEDTLS_X509_MAX_INTERMEDIATE_CA",                  Undefined), // default: 8
    ("MBEDTLS_X509_MAX_FILE_PATH_LEN",                    Undefined), // default: 512
    ("MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES",    Undefined),
    ("MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE",    Defined),
    ("MBEDTLS_PLATFORM_ZEROIZE_ALT",                      Undefined),
    ("MBEDTLS_PLATFORM_GMTIME_R_ALT",                     Undefined),
    ("MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED",              Undefined),
];

pub fn default_defines() -> HashMap<&'static str, Macro> {
    let mut defines = HashMap::new();

    for (key, value) in DEFAULT_DEFINES.iter() {
        if defines.insert(*key, *value).is_some() {
            panic!("Duplicate default define in {}: {}", file!(), key);
        }
    }

    defines
}

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const FEATURE_DEFINES: &'static [(&'static str, CDefine)] = &[
    ("time",                  ("MBEDTLS_HAVE_TIME",                         Defined)),
    ("time",                  ("MBEDTLS_HAVE_TIME_DATE",                    Defined)),
    ("havege",                ("MBEDTLS_HAVEGE_C",                          Defined)),
    ("threading",             ("MBEDTLS_THREADING_C",                       Defined)),
    ("pkcs11",                ("MBEDTLS_PKCS11_C",                          Defined)),
    ("zlib",                  ("MBEDTLS_ZLIB_SUPPORT",                      Defined)),
    ("debug",                 ("MBEDTLS_DEBUG_C",                           Defined)),
    ("custom_printf",         ("MBEDTLS_PLATFORM_C",                        Defined)),
    ("custom_printf",         ("MBEDTLS_PLATFORM_PRINTF_MACRO",             DefinedAs("mbedtls_printf"))),
    ("aesni",                 ("MBEDTLS_AESNI_C",                           Defined)),
    ("padlock",               ("MBEDTLS_PADLOCK_C",                         Defined)),
    ("custom_has_support",    ("MBEDTLS_CUSTOM_HAS_AESNI",                  Defined)),
    ("custom_has_support",    ("MBEDTLS_CUSTOM_HAS_PADLOCK",                Defined)),
    ("legacy_protocols",      ("MBEDTLS_SSL_PROTO_SSL3",                    Defined)),
    ("legacy_protocols",      ("MBEDTLS_SSL_PROTO_TLS1",                    Defined)),
    ("legacy_protocols",      ("MBEDTLS_SSL_PROTO_TLS1_1",                  Defined)),
    ("legacy_protocols",      ("MBEDTLS_SSL_CBC_RECORD_SPLITTING",          Defined)),
    ("aes_alt",               ("MBEDTLS_AES_ENCRYPT_ALT",                   Defined)),
    ("aes_alt",               ("MBEDTLS_AES_DECRYPT_ALT",                   Defined)),
    ("mpi_force_c_code",      ("MBEDTLS_MPI_FORCE_C_CODE",                  Defined)),
    ("trusted_cert_callback", ("MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK", Defined)),
];

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const PLATFORM_DEFINES: &'static [(&'static str, &'static str, CDefine)] = &[
    ("time",      "libc",     ("MBEDTLS_TIMING_C",                          Defined)),
    ("time",      "custom",   ("MBEDTLS_PLATFORM_TIME_MACRO",               DefinedAs("mbedtls_time"))),
    ("time",      "custom",   ("MBEDTLS_PLATFORM_TIME_TYPE_MACRO",          DefinedAs("long long"))),
    ("time",      "custom",   ("MBEDTLS_PLATFORM_GMTIME_R_ALT",             Defined)),
    ("threading", "pthread",  ("MBEDTLS_THREADING_PTHREAD",                 Defined)),
    ("threading", "custom",   ("MBEDTLS_THREADING_IMPL",                    Defined)),
    ("std",       "net",      ("MBEDTLS_NET_C",                             Defined)),
    ("std",       "fs",       ("MBEDTLS_FS_IO",                             Defined)),
    ("std",       "entropy",  ("MBEDTLS_NO_PLATFORM_ENTROPY",               Undefined)),
    ("std",       "entropy",  ("MBEDTLS_ENTROPY_C",                         Defined)),
];

pub const SUFFIX: &'static str = r#"
#if defined(TARGET_LIKE_MBED)
#include "mbedtls/target_config.h"
#endif
#include <mbedtls/check_config.h>
#endif /* MBEDTLS_CONFIG_H */
"#;
