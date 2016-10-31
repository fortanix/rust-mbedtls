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

pub mod ctr_drbg;
pub mod hmac_drbg;
#[cfg(feature="std")]
pub mod os_entropy;
#[cfg(feature="rdrand")]
mod rdrand;

#[doc(inline)]
pub use self::ctr_drbg::CtrDrbg;
#[doc(inline)]
pub use self::hmac_drbg::HmacDrbg;
#[cfg(feature="std")]
#[doc(inline)]
pub use self::os_entropy::OsEntropy;
#[cfg(feature="rdrand")]
pub use self::rdrand::{Entropy as Rdseed,Nrbg as Rdrand};

use mbedtls_sys::types::raw_types::{c_int,c_uchar};
use mbedtls_sys::types::size_t;
use error::IntoResult;

callback!(EntropyCallback:Sync(data: *mut c_uchar, len: size_t) -> c_int);
callback!(RngCallback:Sync(data: *mut c_uchar, len: size_t) -> c_int);

pub trait Random: RngCallback {
	fn random(&mut self, data: &mut [u8]) -> ::Result<()> {
		try!(unsafe{Self::call(self.data_ptr(),data.as_mut_ptr(),data.len())}.into_result());
		Ok(())
	}
}

impl<'r,F: RngCallback> Random for F {}
