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

use core::ptr;
use core::mem;

use mbedtls_sys::types::raw_types::c_void;
use mbedtls_sys::types::size_t;

extern {
	#[no_mangle]
	fn __rust_allocate(size: usize, align: usize) -> *mut u8;

	#[no_mangle]
	fn __rust_deallocate(ptr: *mut u8, old_size: usize, align: usize);
}

// Use the Rust allocator and store the size of the allocation in the first few
// bytes, then return a pointer to the remaining memory (zeroed)
#[no_mangle]
pub unsafe extern "C" fn calloc(n: size_t, size: size_t) -> *mut c_void {
	let usize_size=mem::size_of::<usize>();
	let alloc_size=n*size+usize_size;
	let ptr=__rust_allocate(alloc_size,usize_size) as *mut usize;
	if ptr==ptr::null_mut() {
		return ptr::null_mut();
	}
	ptr::write(ptr,alloc_size);
	let ret=ptr.offset(1) as *mut u8;
	ptr::write_bytes(ret,0,alloc_size-usize_size);
	ret as *mut c_void
}

// The size of the allocation is stored just before the pointed-to memory
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
	if ptr==ptr::null_mut() {
		return
	}
	let ptr=(ptr as *mut usize).offset(-1);
	let usize_size=mem::size_of::<usize>();
	let alloc_size=ptr::read(ptr);
	__rust_deallocate(ptr as *mut u8,alloc_size,usize_size);
}
