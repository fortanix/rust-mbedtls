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

#[cfg(feature="collections")] use core::fmt;

use mbedtls_sys::*;

use error::IntoResult;

define!(
/// Certificate Revocation List
struct Crl(x509_crl) {
	pub fn new=x509_crl_init;
	fn drop=x509_crl_free;
	impl<'a> Into<*>;
});

impl Crl {
	pub fn push_from_der(&mut self, der: &[u8]) -> ::Result<()> {
		unsafe{x509_crl_parse_der(&mut self.inner,der.as_ptr(),der.len()).into_result().map(|_|())}
	}

	pub fn push_from_pem(&mut self, pem: &[u8]) -> ::Result<()> {
		unsafe{x509_crl_parse(&mut self.inner,pem.as_ptr(),pem.len()).into_result().map(|_|())}
	}
}

#[cfg(feature="collections")]
impl fmt::Debug for Crl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match ::private::alloc_string_repeat(|buf,size|unsafe{x509_crl_info(buf,size,b"\0".as_ptr() as *const _,&self.inner)}) {
			Err(_) => Err(fmt::Error),
			Ok(s) => f.write_str(&s),
		}
	}
}

/*
TODO
x509_crl_parse_file
*/
