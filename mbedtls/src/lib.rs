/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![deny(warnings)]
#![allow(unused_doc_comments)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), not(feature = "core-io")))]
const ERROR: _MUST_USE_EITHER_STD_OR_CORE_IO_ = ();

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate core;
#[cfg(not(feature = "std"))]
extern crate core_io;

#[cfg(feature = "std")]
extern crate yasna;

#[macro_use]
extern crate bitflags;
extern crate mbedtls_sys;

extern crate byteorder;

extern crate serde;
#[macro_use]
extern crate serde_derive;

#[cfg(target_env = "sgx")]
extern crate rs_libc;

#[macro_use]
mod wrapper_macros;

#[cfg(feature = "pkcs12_rc2")]
extern crate cbc;
#[cfg(feature = "pkcs12_rc2")]
extern crate rc2;

// ==============
//      API
// ==============
pub mod bignum;
mod error;
pub use crate::error::{Error, Result};
pub mod cipher;
pub mod ecp;
pub mod hash;
pub mod pk;
pub mod rng;
pub mod self_test;
pub mod ssl;
pub mod x509;

#[cfg(feature = "pkcs12")]
pub mod pkcs12;

// ==============
//    Utility
// ==============
mod private;

// needs to be pub for global visiblity
#[cfg(any(feature = "spin_threading", feature = "rust_threading"))]
#[doc(hidden)]
pub use mbedtls_platform_support::threading as threading;

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
pub use mbedtls_platform_support::mbedtls_aesni_has_support;

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
pub use mbedtls_platform_support::mbedtls_internal_aes_encrypt;

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
pub use mbedtls_platform_support::mbedtls_internal_aes_decrypt;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod mbedtls {
    pub use super::*;
}

#[cfg(not(feature = "std"))]
mod alloc_prelude {
    #![allow(unused)]
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::String;
    pub(crate) use alloc::string::ToString;
    pub(crate) use alloc::vec::Vec;
}

#[cfg(feature="custom_gmtime_r")]
#[doc(hidden)]
pub use mbedtls_platform_support::mbedtls_platform_gmtime_r;

#[cfg(feature="custom_time")]
#[doc(hidden)]
pub use mbedtls_platform_support::mbedtls_time;
