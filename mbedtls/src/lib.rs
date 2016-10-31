/*
 * Rust interface for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![allow(drop_with_repr_extern)] // for pk::Pk
#![cfg_attr(feature="rdrand",feature(asm))]
#![cfg_attr(all(not(feature="std"),feature="collections"),feature(collections))]
#![cfg_attr(not(feature="std"),feature(alloc))]
#![cfg_attr(not(feature="std"),no_std)]

#[cfg(all(not(feature="std"),not(feature="core_io")))]
extern crate _MUST_USE_EITHER_STD_OR_CORE_IO_;

//see cargo bug #1286
#[cfg(all(feature="core_io",feature="collections",not(feature="core_io_collections")))]
const ERROR: _WHEN_USING_CORE_IO_MUST_ENABLE_CORE_IO_COLLECTIONS_ = ();

#[cfg(feature="std")]
extern crate core;
#[cfg(not(feature="std"))]
extern crate core_io;
#[cfg(not(feature="std"))]
extern crate alloc;
#[cfg(all(not(feature="std"),feature="collections"))]
extern crate collections;

#[macro_use]
extern crate bitflags;
extern crate mbedtls_sys;

#[macro_use]
mod wrapper_macros;

// ==============
//      API
// ==============
#[allow(dead_code)] // to be exported once the API is more complete
mod bignum;
mod error;
pub use error::{Error,Result};
pub mod hash;
pub mod pk;
pub mod rng;
pub mod ssl;
pub mod x509;

// ==============
//    Utility
// ==============
mod private;

// needs to be pub for global visiblity
#[cfg(feature="spin_threading")]
#[doc(hidden)]
pub mod threading;

// needs to be pub for global visiblity
#[cfg(not(feature="std"))]
#[doc(hidden)]
pub mod no_std;
#[cfg(not(feature="std"))]
pub use no_std::self_test;

// needs to be pub for global visiblity
#[cfg(feature="std")]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_log(msg: *const std::os::raw::c_char) {
	print!("{}",std::ffi::CStr::from_ptr(msg).to_string_lossy());
}

// needs to be pub for global visiblity
#[cfg(feature="force_aesni_support")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
	return 1;
}

#[cfg(test)]
#[path="../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod mbedtls {
	pub use super::*;
}
