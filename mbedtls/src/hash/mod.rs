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

use mbedtls_sys::*;
use error::IntoResult;

define!(enum Type -> md_type_t {
	None => MD_NONE,
	Md2 => MD_MD2,
	Md4 => MD_MD4,
	Md5 => MD_MD5,
	Sha1 => MD_SHA1,
	Sha224 => MD_SHA224,
	Sha256 => MD_SHA256,
	Sha384 => MD_SHA384,
	Sha512 => MD_SHA512,
	Ripemd => MD_RIPEMD160,
});

#[derive(Copy,Clone)]
pub struct MdInfo {
	inner: &'static md_info_t
}

impl Into<Option<MdInfo>> for Type {
	fn into(self) -> Option<MdInfo> {
		unsafe{md_info_from_type(self.into()).as_ref()}.map(|r|MdInfo{inner:r})
	}
}

impl Into<*const md_info_t> for MdInfo {
	fn into(self) -> *const md_info_t {
		self.inner
	}
}

define!(struct Md(md_context_t) {
	fn init=md_init;
	fn drop=md_free;
	impl<'a> Into<*>;
});

impl Md {
	pub fn new(md: Type) -> ::Result<Md> {
		let md: MdInfo=match md.into() {
			Some(md) => md,
			None => return Err(::Error::MdBadInputData),
		};

		let mut ctx=Md::init();
		unsafe{
			try!(md_setup(&mut ctx.inner,md.into(),0).into_result());
			try!(md_starts(&mut ctx.inner).into_result());
		}
		Ok(ctx)
	}

	pub fn hash(md: Type, data: &[u8], out: &mut [u8]) -> ::Result<usize> {
		let md: MdInfo=match md.into() {
			Some(md) => md,
			None => return Err(::Error::MdBadInputData),
		};

		unsafe {
			let olen=md.inner.size as usize;
			if out.len()<olen {
				return Err(::Error::MdBadInputData);
			}
			try!(::mbedtls_sys::md(md.inner,data.as_ptr(),data.len(),out.as_mut_ptr()).into_result());
			Ok(olen)
		}
	}
}

pub fn pbkdf2_hmac(md: Type, password: &[u8], salt: &[u8], iterations: u32, key: &mut [u8]) -> ::Result<()> {
	let md: MdInfo=match md.into() {
		Some(md) => md,
		None => return Err(::Error::MdBadInputData),
	};
	
	unsafe {
		let mut ctx=Md::init();
		try!(md_setup((&mut ctx).into(),md.into(),1).into_result());
		try!(pkcs5_pbkdf2_hmac((&mut ctx).into(),password.as_ptr(),password.len(),salt.as_ptr(),salt.len(),iterations,key.len() as u32,key.as_mut_ptr()).into_result());
		Ok(())
	}
}
