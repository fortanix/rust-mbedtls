/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "std")]
extern crate core;

pub mod types;
include!(concat!(env!("OUT_DIR"), "/mod-bindings.rs"));

pub use bindings::*;

/* This value is defined by a C function macro, something which is not supported by bindgen currently
   https://github.com/rust-lang-nursery/rust-bindgen/issues/231
*/
pub const ECDSA_MAX_LEN : u32 = 141;

#[cfg(all(feature = "time", not(feature = "custom_time"), not(feature = "libc")))]
impl _ERROR_MUST_ENABLE_EITHER_CUSTOM_TIME_OR_LIBC_ for _TIME_FEATURE_ {}

#[cfg(all(feature = "time", not(feature = "custom_gmtime_r"), not(feature = "libc")))]
impl _ERROR_MUST_ENABLE_EITHER_CUSTOM_GMTIME_R_OR_LIBC_ for _TIME_FEATURE_ {}
