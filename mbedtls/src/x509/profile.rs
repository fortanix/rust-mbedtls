/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::*;
use crate::{hash, pk};

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

define!(
    #[c_ty(x509_crt_profile)]
    #[repr(C)]
    struct Profile;
    impl<'a> Into<ptr> {}
);

impl Profile {
    pub fn new(hash_types: Vec<hash::Type>, pk_types: Vec<pk::Type>, curves: Vec<pk::EcGroupId>, rsa_min_bitlen: u32) -> Self {
        let mut allowed_mds = 0u32;
        let mut allowed_pks = 0u32;
        let mut allowed_curves = 0u32;
        for md in hash_types {
            allowed_mds |= 1 << (md as u32 - 1);
        }
        for algo in pk_types {
            allowed_pks |= 1 << (algo as u32 - 1);
        }
        for curve in curves {
            allowed_curves |= 1 << (curve as u32 - 1);
        }
        Profile {
            inner: x509_crt_profile {
                allowed_mds,
                allowed_pks,
                allowed_curves,
                rsa_min_bitlen,
            }
        }
    }
}

extern "C" {
    #[link_name = "mbedtls_x509_crt_profile_default"]
    pub static DEFAULT: Profile;
    #[link_name = "mbedtls_x509_crt_profile_next"]
    pub static NEXT: Profile;
    #[link_name = "mbedtls_x509_crt_profile_suiteb"]
    pub static SUITE_B: Profile;
}
