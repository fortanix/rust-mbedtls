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

use mbedtls_sys::types::raw_types::{c_int,c_uchar,c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::{ctr_drbg_seed,ctr_drbg_set_prediction_resistance,ctr_drbg_reseed,ctr_drbg_update,ctr_drbg_random,CTR_DRBG_PR_OFF,CTR_DRBG_PR_ON};
pub use mbedtls_sys::CTR_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;

use super::{EntropyCallback,RngCallback};
use error::IntoResult;

define!(struct CtrDrbg<'entropy>(ctr_drbg_context) {
	fn init=ctr_drbg_init;
	fn drop=ctr_drbg_free;
});

#[cfg(feature="threading")]
unsafe impl<'entropy> Sync for CtrDrbg<'entropy> {}

impl<'entropy> CtrDrbg<'entropy> {
	pub fn new<F: EntropyCallback>(source: &'entropy mut F, additional_entropy: Option<&[u8]>) -> ::Result<CtrDrbg<'entropy>> {
		let mut ret=Self::init();
		unsafe{try!(ctr_drbg_seed(
			&mut ret.inner,
			Some(F::call),
			source.data_ptr(),
			additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
			additional_entropy.map(<[_]>::len).unwrap_or(0)
		).into_result())};
		Ok(ret)
	}
	
	pub fn prediction_resistance(&self) -> bool {
		if self.inner.prediction_resistance==CTR_DRBG_PR_OFF { false } else { true }
	}
	
	pub fn set_prediction_resistance(&mut self, pr: bool) {
		unsafe{ctr_drbg_set_prediction_resistance(&mut self.inner,if pr { CTR_DRBG_PR_ON } else { CTR_DRBG_PR_OFF })}
	}
	
	getter!(entropy_len() -> size_t = .entropy_len);
	setter!(set_entropy_len(len: size_t) = ctr_drbg_set_entropy_len);
	getter!(reseed_interval() -> c_int = .reseed_interval);
	setter!(set_reseed_interval(i: c_int) = ctr_drbg_set_reseed_interval);

	pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> ::Result<()> {
		unsafe{try!(ctr_drbg_reseed(
			&mut self.inner,
			additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
			additional_entropy.map(<[_]>::len).unwrap_or(0)
		).into_result())};
		Ok(())
	}

	pub fn update(&mut self, entropy: &[u8]) {
		unsafe{ctr_drbg_update(&mut self.inner,entropy.as_ptr(),entropy.len())};
	}

/*
TODO:

ctr_drbg_random_with_add
ctr_drbg_write_seed_file
ctr_drbg_update_seed_file
*/
}

impl<'entropy> RngCallback for CtrDrbg<'entropy> {
	#[inline(always)]
	unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
		ctr_drbg_random(user_data,data,len)
	}

	fn data_ptr(&mut self) -> *mut c_void {
		&mut self.inner as *mut _ as *mut _
	}
}
