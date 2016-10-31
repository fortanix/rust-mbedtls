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

//! Calling mbedTLS self-test functions before they're enabled using the
//! `enable()` function here will result in a panic.
use mbedtls_sys::types::raw_types::{c_int,c_char};

static mut rand_f: Option<fn() -> c_int> = None;
static mut log_f: Option<unsafe fn(*const c_char)> = None;

// needs to be pub for global visiblity
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn rand() -> c_int {
	rand_f.expect("Called self-test rand without enabling self-test")()
}

// needs to be pub for global visiblity
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_log(msg: *const c_char) {
	log_f.expect("Called self-test log without enabling self-test")(msg)
}

// unsafe since unsynchronized
pub unsafe fn enable(rand: fn() -> c_int, log: unsafe fn(*const c_char)) {
	rand_f=Some(rand);
	log_f=Some(log);
}

// unsafe since unsynchronized
pub unsafe fn disable() {
	rand_f=None;
	log_f=None;
}
