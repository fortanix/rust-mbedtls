/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![deny(warnings)]
#![cfg_attr(feature = "rdrand", feature(asm))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), not(feature = "core_io")))]
const ERROR: _MUST_USE_EITHER_STD_OR_CORE_IO_ = ();

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate core;
#[cfg(not(feature = "std"))]
extern crate core_io;

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

#[cfg(feature = "pkcs12")]
extern crate yasna;

#[cfg(feature="pkcs12_rc2")]
extern crate rc2;
#[cfg(feature="pkcs12_rc2")]
extern crate block_modes;

// ==============
//      API
// ==============
pub mod bignum;
mod error;
pub use error::{Error, Result};
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
pub mod threading;

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
    return 1;
}

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
