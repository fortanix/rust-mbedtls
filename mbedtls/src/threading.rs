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

extern crate spin;
use self::spin::{Mutex,MutexGuard};
#[cfg(not(feature="std"))]
use alloc::boxed::Box;

use mbedtls_sys::types::raw_types::c_int;

pub struct StaticMutex {
	// Storing these alongside because guards are only ever created for mutexes
	// in a Box, meaning their address is stable. We take care to drop the guard
	// before the mutex is potentially moved again.
	guard: Option<MutexGuard<'static,()>>,
	mutex: Mutex<()>,
}

#[no_mangle] pub static mut mbedtls_mutex_init:   unsafe extern "C" fn(mutex: *mut *mut StaticMutex)          = StaticMutex::init;
#[no_mangle] pub static mut mbedtls_mutex_free:   unsafe extern "C" fn(mutex: *mut *mut StaticMutex)          = StaticMutex::free;
#[no_mangle] pub static mut mbedtls_mutex_lock:   unsafe extern "C" fn(mutex: *mut *mut StaticMutex) -> c_int = StaticMutex::lock;
#[no_mangle] pub static mut mbedtls_mutex_unlock: unsafe extern "C" fn(mutex: *mut *mut StaticMutex) -> c_int = StaticMutex::unlock;

impl StaticMutex {
	unsafe extern "C" fn init(mutex: *mut *mut StaticMutex) {
		if let Some(m)=mutex.as_mut() {
			*m=Box::into_raw(Box::new(StaticMutex{guard:None,mutex:Mutex::new(())}));
		}
	}

	unsafe extern "C" fn free(mutex: *mut *mut StaticMutex) {
		if let Some((p,m))=mutex.as_mut().and_then(|p|p.as_mut().map(|m|(p,m))) {
			m.guard.take(); // potentially drop guard
			let mut mutex=Box::<StaticMutex>::from_raw(m); // this will drop
			*p=::core::ptr::null_mut();
		}
	}

	unsafe extern "C" fn lock(mutex: *mut *mut StaticMutex) -> c_int {
		if let Some(m)=mutex.as_mut().and_then(|p|p.as_mut()) {
			let guard=m.mutex.lock();
			m.guard=Some(guard);
			0
		} else {
			::mbedtls_sys::ERR_THREADING_BAD_INPUT_DATA
		}
	}
	
	unsafe extern "C" fn unlock(mutex: *mut *mut StaticMutex) -> c_int {
		if let Some(m)=mutex.as_mut().and_then(|p|p.as_mut()) {
			m.guard.take();
			0
		} else {
			::mbedtls_sys::ERR_THREADING_BAD_INPUT_DATA
		}
	}
}
