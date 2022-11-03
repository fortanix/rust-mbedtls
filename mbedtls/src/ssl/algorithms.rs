/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::c_int;
use mbedtls_sys::*;

/// Always use into() to convert to i32, do not use 'as i32'. (until issue is fixed: https://github.com/fortanix/rust-mbedtls/issues/129)
define!(
    #[non_exhaustive]
    #[c_ty(c_int)]
    enum TLS1_3SignatureAlgorithms {
        RsaPkcs1Sha256 = TLS1_3_SIG_RSA_PKCS1_SHA256,
        RsaPkcs1Sha384 = TLS1_3_SIG_RSA_PKCS1_SHA384,
        RsaPkcs1Sha512 = TLS1_3_SIG_RSA_PKCS1_SHA512,
        EcdsaSecp256R1Sha256 = TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
        EcdsaSecp384R1Sha384 = TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
        EcdsaSecp521R1Sha512 = TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
        RsaPssRsaeSha256 = TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
        RsaPssRsaeSha384 = TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
        RsaPssRsaeSha512 = TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
        Ed25519 = TLS1_3_SIG_ED25519,
        Ed448 = TLS1_3_SIG_ED448,
        RsaPssPssSha256 = TLS1_3_SIG_RSA_PSS_PSS_SHA256,
        RsaPssPssSha384 = TLS1_3_SIG_RSA_PSS_PSS_SHA384,
        RsaPssPssSha512 = TLS1_3_SIG_RSA_PSS_PSS_SHA512,
        RsaPkcs1Sha1 = TLS1_3_SIG_RSA_PKCS1_SHA1,
        EcdsaSha1 = TLS1_3_SIG_ECDSA_SHA1,
        None = TLS1_3_SIG_NONE,
    }
);

use TLS1_3SignatureAlgorithms::*;
pub fn tls1_3_preset_default_sig_algs() -> Vec<u16> {
    vec![
    Into::<c_int>::into(EcdsaSecp256R1Sha256) as u16,
    Into::<c_int>::into(EcdsaSecp384R1Sha384) as u16,
    Into::<c_int>::into(EcdsaSecp521R1Sha512) as u16,
    Into::<c_int>::into(RsaPkcs1Sha256) as u16,
    Into::<c_int>::into(RsaPkcs1Sha384) as u16,
    Into::<c_int>::into(RsaPkcs1Sha512) as u16,
    Into::<c_int>::into(RsaPssRsaeSha256) as u16,
    Into::<c_int>::into(RsaPssRsaeSha384) as u16,
    Into::<c_int>::into(RsaPssRsaeSha512) as u16,
    Into::<c_int>::into(None) as u16,
    ]
}
