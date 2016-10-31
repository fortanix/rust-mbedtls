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

extern crate rand;
extern crate mbedtls_sys;
extern crate core;

use self::mbedtls_sys::types::raw_types::{c_int,c_uchar,c_void};
use self::mbedtls_sys::types::size_t;

use self::rand::{Rng,XorShiftRng};

/// Not cryptographically secure!!! Not actually random!!! Deterministic!!! Use for testing only!!!
pub struct TestRandom(XorShiftRng);

impl ::mbedtls::rng::RngCallback for TestRandom {
	unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
		(*(p_rng as *mut TestRandom)).0.fill_bytes(self::core::slice::from_raw_parts_mut(data,len));
		0
	}

	fn data_ptr(&mut self) -> *mut c_void {
		self as *mut _ as *mut _
	}
}

/// Not cryptographically secure!!! Not actually random!!! Deterministic!!! Use for testing only!!!
pub fn test_rng() -> TestRandom {
	TestRandom(XorShiftRng::new_unseeded())
}
