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

#[cfg(all(not(feature="std"),feature="collections"))] use collections::vec::Vec;
#[cfg(all(not(feature="std"),feature="collections"))] use collections::string::String;

#[cfg(feature="collections")] use mbedtls_sys::types::raw_types::{c_int,c_uchar};
use mbedtls_sys::types::raw_types::c_char;
use mbedtls_sys::types::size_t;

#[cfg(feature="collections")] use error::IntoResult;

pub trait UnsafeFrom<T> where Self: Sized {
    unsafe fn from(T) -> Option<Self>;
}

#[cfg(feature="collections")]
pub fn alloc_vec_repeat<F>(mut f: F, data_at_end: bool) -> ::Result<Vec<u8>> where F: FnMut(*mut c_uchar,size_t) -> c_int {
	let mut vec=Vec::with_capacity(512); // must have capacity > 0
	loop { 
		match f(vec.as_mut_ptr(),vec.capacity()).into_result() {
			Err(::Error::Asn1BufTooSmall) | Err(::Error::Base64BufferTooSmall) |
			Err(::Error::EcpBufferTooSmall) | Err(::Error::MpiBufferTooSmall) |
			Err(::Error::NetBufferTooSmall) | Err(::Error::OidBufTooSmall) |
			Err(::Error::SslBufferTooSmall) | Err(::Error::X509BufferTooSmall)
				=> {let cap=vec.capacity();vec.reserve(cap*2)},
			Err(e) => return Err(e),
			Ok(n) => {
				if data_at_end {
					let len=vec.capacity();
					unsafe{vec.set_len(len)};
					drop(vec.drain(..len-(n as usize)));
				} else {
					unsafe{vec.set_len(n as usize)};
				}
				break;
			}
		}
	}
	vec.shrink_to_fit();
	Ok(vec)
}

#[cfg(feature="collections")]
pub fn alloc_string_repeat<F>(mut f: F) -> ::Result<String> where F: FnMut(*mut c_char,size_t) -> c_int {
	let vec=try!(alloc_vec_repeat(|b,s|f(b as _,s),false));
	String::from_utf8(vec).map_err(|e|e.utf8_error().into())
}

#[cfg(feature="std")]
pub unsafe fn cstr_to_slice<'a>(ptr: *const c_char) -> &'a [u8] {
    ::std::ffi::CStr::from_ptr(ptr).to_bytes()
}

#[cfg(not(feature="std"))]
pub unsafe fn cstr_to_slice<'a>(ptr: *const c_char) -> &'a [u8] {
    extern "C" {
		// this function is coming from the mbedtls C support lib
        fn strlen(s: *const c_char) -> size_t;
    }
    ::core::slice::from_raw_parts(ptr as *const _,strlen(ptr))
}

#[cfg(feature="std")]
use std::io::{Error as IoError,ErrorKind as IoErrorKind};
#[cfg(not(feature="std"))]
use core_io::{Error as IoError,ErrorKind as IoErrorKind};

#[cfg(feature="collections")]
pub fn error_to_io_error(e: ::Error) -> IoError {
    #[cfg(not(feature="std"))] use collections::string::ToString;
    IoError::new(IoErrorKind::Other,e.to_string())
}

#[cfg(not(feature="collections"))]
pub fn error_to_io_error(e: ::Error) -> IoError {
    IoError::new(IoErrorKind::Other,e.as_str())
}
