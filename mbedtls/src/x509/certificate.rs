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
use core::marker::PhantomData;
use core::ops::{Deref,DerefMut};

#[cfg(all(not(feature="std"),feature="collections"))] use collections::vec::Vec;
#[cfg(all(not(feature="std"),feature="collections"))] use collections::string::String;

use mbedtls_sys::types::raw_types::c_char;
use mbedtls_sys::*;

use error::IntoResult;
use private::UnsafeFrom;

define!(struct Certificate(x509_crt) {
	fn init=x509_crt_init;
	fn drop=x509_crt_free;
});

impl Certificate {
	pub fn from_der(der: &[u8]) -> ::Result<Certificate> {
		let mut ret=Self::init();
		unsafe{try!(x509_crt_parse_der(&mut ret.inner,der.as_ptr(),der.len()).into_result())};
		Ok(ret)
	}

	/// Input must be NULL-terminated
	pub fn from_pem(pem: &[u8]) -> ::Result<Certificate> {
		let mut ret=Self::init();
		unsafe{try!(x509_crt_parse(&mut ret.inner,pem.as_ptr(),pem.len()).into_result())};
		let mut fake=Self::init();
		::core::mem::swap(&mut fake.inner.next,&mut ret.inner.next);
		Ok(ret)
	}

	/// Input must be NULL-terminated
	#[cfg(feature="collections")]
	pub fn from_pem_multiple(pem: &[u8]) -> ::Result<Vec<Certificate>> {
		let mut vec;
		unsafe{
			// first, find out how many certificates we're parsing
			let mut dummy=Certificate::init();
			try!(x509_crt_parse(&mut dummy.inner,pem.as_ptr(),pem.len()).into_result());
			
			// then allocate enough certs with our allocator
			vec=Vec::new();
			let mut cur: *mut _=&mut dummy.inner;
			while cur != ::core::ptr::null_mut() {
				vec.push(Certificate::init());
				cur=(*cur).next;
			};
			
			// link them together, they will become unlinked again when List drops
			let list=List::from_slice(&mut vec).unwrap();
			
			// load the data again but into our allocated list
			try!(x509_crt_parse(&mut list.head.inner,pem.as_ptr(),pem.len()).into_result());
		};
		Ok(vec)
	}
}

impl Deref for Certificate {
	type Target = LinkedCertificate;
	fn deref(&self) -> &LinkedCertificate {
		unsafe{UnsafeFrom::from(&self.inner as *const _).unwrap()}
	}
}

impl DerefMut for Certificate {
	fn deref_mut(&mut self) -> &mut LinkedCertificate {
		unsafe{UnsafeFrom::from(&mut self.inner as *mut _).unwrap()}
	}
}

#[repr(C)]
pub struct LinkedCertificate {
	inner: x509_crt,
}

impl LinkedCertificate {
	pub fn check_key_usage(&self, usage: super::KeyUsage) -> bool {
		unsafe{x509_crt_check_key_usage(&self.inner,usage.bits())}.into_result().is_ok()
	}
	
	pub fn check_extended_key_usage(&self, usage_oid: &[c_char]) -> bool {
		unsafe{x509_crt_check_extended_key_usage(&self.inner,usage_oid.as_ptr(),usage_oid.len())}.into_result().is_ok()
	}

	#[cfg(feature="collections")]
	pub fn issuer(&self) -> ::Result<String> {
		::private::alloc_string_repeat(|buf,size|unsafe{x509_dn_gets(buf,size,&self.inner.issuer)})
	}

	#[cfg(feature="collections")]
	pub fn subject(&self) -> ::Result<String> {
		::private::alloc_string_repeat(|buf,size|unsafe{x509_dn_gets(buf,size,&self.inner.subject)})
	}

	#[cfg(feature="collections")]
	pub fn serial(&self) -> ::Result<String> {
		::private::alloc_string_repeat(|buf,size|unsafe{x509_serial_gets(buf,size,&self.inner.serial)})
	}
	
	pub fn public_key(&self) -> &::pk::Pk {
		unsafe{&*(&self.inner.pk as *const _ as *const _)}
	}
}

/*
TODO

x509_crt_verify_info
x509_crt_verify
x509_crt_verify_with_profile
x509_crt_is_revoked

x509_crt_parse_file
x509_crt_parse_path
*/

#[cfg(feature="collections")]
impl fmt::Debug for LinkedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match ::private::alloc_string_repeat(|buf,size|unsafe{x509_crt_info(buf,size,b"\0".as_ptr() as *const _,&self.inner)}) {
			Err(_) => Err(fmt::Error),
			Ok(s) => f.write_str(&s),
		}
	}
}

impl<'r> Into<*const x509_crt> for &'r LinkedCertificate {
	fn into(self) -> *const x509_crt {
		&self.inner
	}
}

impl<'r> Into<*mut x509_crt> for &'r mut LinkedCertificate {
	fn into(self) -> *mut x509_crt {
		&mut self.inner
	}
}

impl<'r> UnsafeFrom<*const x509_crt> for &'r LinkedCertificate {
	unsafe fn from(ptr: *const x509_crt) -> Option<&'r LinkedCertificate> {
		(ptr as *const _).as_ref()
	}
}

impl<'r> UnsafeFrom<*mut x509_crt> for &'r mut LinkedCertificate {
	unsafe fn from(ptr: *mut x509_crt) -> Option<&'r mut LinkedCertificate> {
		(ptr as *mut _).as_mut()
	}
}

pub struct Iter<'a> {
	next: *const x509_crt,
	r: PhantomData<&'a x509_crt>,
}

impl<'a> Iterator for Iter<'a> {
	type Item = &'a LinkedCertificate;
	
	fn next(&mut self) -> Option<&'a LinkedCertificate> {
		unsafe {
			match self.next {
				p if p==::core::ptr::null() => None,
				p => {
					self.next=(*p).next as *const _;
					Some(UnsafeFrom::from(p).unwrap())
				},
			}
		}
	}
}

pub struct IterMut<'a> {
	next: *mut x509_crt,
	r: PhantomData<&'a mut x509_crt>,
}

impl<'a> Iterator for IterMut<'a> {
	type Item = &'a mut LinkedCertificate;
	
	fn next(&mut self) -> Option<&'a mut LinkedCertificate> {
		unsafe {
			match self.next {
				p if p==::core::ptr::null_mut() => None,
				p => {
					self.next=(*p).next;
					Some(UnsafeFrom::from(p).unwrap())
				},
			}
		}
	}
}

pub struct List<'c> {
	head: &'c mut Certificate,
}

impl<'c> List<'c> {
	pub fn iter<'i>(&'i self) -> Iter<'i> {
		Iter{next:&self.head.inner,r:PhantomData}
	}

	pub fn iter_mut<'i>(&'i mut self) -> IterMut<'i> {
		IterMut{next:&mut self.head.inner,r:PhantomData}
	}
	
	pub fn push_front(&mut self, cert: &'c mut Certificate) {
		assert!(cert.inner.next==::core::ptr::null_mut());
		cert.inner.next=&mut self.head.inner;
		self.head=cert;
	}

	pub fn push_back(&mut self, cert: &'c mut Certificate) {
		assert!(cert.inner.next==::core::ptr::null_mut());
		for c in self.iter_mut() {
			if c.inner.next==::core::ptr::null_mut() {
				c.inner.next=&mut cert.inner;
				break;
			}
		}
	}

	pub fn append(&mut self, list: List<'c>) {
		assert!(list.head.inner.next==::core::ptr::null_mut());
		for c in self.iter_mut() {
			if c.inner.next==::core::ptr::null_mut() {
				c.inner.next=&mut list.head.inner;
				break;
			}
		}
		::core::mem::forget(list);
	}
	
	pub fn from_slice(s: &'c mut [Certificate]) -> Option<List<'c>> {
		s.split_first_mut().map(|(first,rest)|{
			let mut list=List::from(first);
			for c in rest {
				list.push_back(c);
			}
			list
		})
	}
}

impl<'c> Drop for List<'c> {
	fn drop(&mut self) {
		// we don't own the certificates, we just need to make sure that
		// x509_crt_free isn't going to try to deallocate our linked certs
		for c in self.iter_mut() {
			c.inner.next=::core::ptr::null_mut();
		}
	}
}

impl<'c> From<&'c mut Certificate> for List<'c> {
	fn from(cert: &'c mut Certificate) -> List<'c> {
		List{head:cert}
	}
}

impl<'c,'r> From<&'c mut List<'r>> for &'c mut LinkedCertificate {
	fn from(list: &'c mut List<'r>) -> &'c mut LinkedCertificate {
		list.head
	}
}

define!(struct Builder<'a>(x509write_cert) {
	pub fn new=x509write_crt_init;
	fn drop=x509write_crt_free;
});

impl<'a> Builder<'a> {
	unsafe fn subject_with_nul_unchecked(&mut self, subject: &[u8]) -> ::Result<&mut Self> {
		try!(x509write_crt_set_subject_name(&mut self.inner,subject.as_ptr() as *const _).into_result());
		Ok(self)
	}
	
	#[cfg(feature="std")]
	pub fn subject(&mut self, subject: &str) -> ::Result<&mut Self> {
		match ::std::ffi::CString::new(subject) {
			Err(_) => Err(::Error::X509InvalidName),
			Ok(s) => unsafe{self.subject_with_nul_unchecked(s.as_bytes_with_nul())},
		}
	}

	pub fn subject_with_nul(&mut self, subject: &str) -> ::Result<&mut Self> {
		if subject.as_bytes().iter().any(|&c|c==0) {
			unsafe{self.subject_with_nul_unchecked(subject.as_bytes())}
		} else {
			Err(::Error::X509InvalidName)
		}
	}
	
	unsafe fn issuer_with_nul_unchecked(&mut self, issuer: &[u8]) -> ::Result<&mut Self> {
		try!(x509write_crt_set_issuer_name(&mut self.inner,issuer.as_ptr() as *const _).into_result());
		Ok(self)
	}
	
	#[cfg(feature="std")]
	pub fn issuer(&mut self, issuer: &str) -> ::Result<&mut Self> {
		match ::std::ffi::CString::new(issuer) {
			Err(_) => Err(::Error::X509InvalidName),
			Ok(s) => unsafe{self.issuer_with_nul_unchecked(s.as_bytes_with_nul())},
		}
	}

	pub fn issuer_with_nul(&mut self, issuer: &str) -> ::Result<&mut Self> {
		if issuer.as_bytes().iter().any(|&c|c==0) {
			unsafe{self.issuer_with_nul_unchecked(issuer.as_bytes())}
		} else {
			Err(::Error::X509InvalidName)
		}
	}
	
	pub fn subject_key(&mut self, key: &'a mut ::pk::Pk) -> &mut Self {
		unsafe{x509write_crt_set_subject_key(&mut self.inner,key.into())};
		self
	}
	
	pub fn issuer_key(&mut self, key: &'a mut ::pk::Pk) -> &mut Self {
		unsafe{x509write_crt_set_issuer_key(&mut self.inner,key.into())};
		self
	}
	
	pub fn signature_hash(&mut self, md: ::hash::Type) -> &mut Self {
		unsafe{x509write_crt_set_md_alg(&mut self.inner,md.into())};
		self
	}
	
	pub fn key_usage(&mut self, usage: ::x509::KeyUsage) -> ::Result<&mut Self> {
		unsafe{try!(x509write_crt_set_key_usage(&mut self.inner,usage.bits()).into_result())};
		Ok(self)
	}

	pub fn extension(&mut self, oid: &[u8], val: &[u8], critical: bool) -> ::Result<&mut Self> {
		unsafe{try!(x509write_crt_set_extension(&mut self.inner,oid.as_ptr() as *const _,oid.len(),critical as _,val.as_ptr(),val.len()).into_result())};
		Ok(self)
	}

	pub fn basic_constraints(&mut self, ca: bool, pathlen: Option<u32>) -> ::Result<&mut Self> {
		unsafe{try!(x509write_crt_set_basic_constraints(&mut self.inner,ca as _,pathlen.unwrap_or(0) as _).into_result())};
		Ok(self)
	}

	pub fn validity(&mut self, not_before: super::Time, not_after: super::Time) -> ::Result<&mut Self> {
		unsafe{try!(x509write_crt_set_validity(&mut self.inner,not_before.to_x509_time().as_ptr() as _,not_after.to_x509_time().as_ptr() as _).into_result())};
		Ok(self)
	}

	pub fn serial(&mut self, serial: &[u8]) -> ::Result<&mut Self> {
		let serial=try!(::bignum::Mpi::from_binary(serial));
		unsafe{try!(x509write_crt_set_serial(&mut self.inner,(&serial).into()).into_result())};
		Ok(self)
	}

	pub fn write_der<'buf, F: ::rng::Random>(&mut self, buf: &'buf mut [u8], rng: &mut F) -> ::Result<Option<&'buf [u8]>> {
		match unsafe{x509write_crt_der(&mut self.inner,buf.as_mut_ptr(),buf.len(),Some(F::call),rng.data_ptr()).into_result()} {
			Err(::Error::Asn1BufTooSmall) => Ok(None),
			Err(e) => Err(e),
			Ok(n) => Ok(Some(&buf[buf.len()-(n as usize)..]))
		}
	}

	#[cfg(feature="collections")]
	pub fn write_der_vec<F: ::rng::Random>(&mut self, rng: &mut F) -> ::Result<Vec<u8>> {
		::private::alloc_vec_repeat(|buf,size|unsafe{x509write_crt_der(&mut self.inner,buf,size,Some(F::call),rng.data_ptr())},true)
	}

	pub fn write_pem<'buf, F: ::rng::Random>(&mut self, buf: &'buf mut [u8], rng: &mut F) -> ::Result<Option<&'buf [u8]>> {
		match unsafe{x509write_crt_pem(&mut self.inner,buf.as_mut_ptr(),buf.len(),Some(F::call),rng.data_ptr()).into_result()} {
			Err(::Error::Base64BufferTooSmall) => Ok(None),
			Err(e) => Err(e),
			Ok(_) => Ok(Some(unsafe{::private::cstr_to_slice(buf.as_ptr() as _)}))
		}
	}

	#[cfg(feature="collections")]
	pub fn write_pem_string<F: ::rng::Random>(&mut self, rng: &mut F) -> ::Result<String> {
		::private::alloc_string_repeat(|buf,size| unsafe{
			match x509write_crt_pem(&mut self.inner,buf as _,size,Some(F::call),rng.data_ptr()) {
				0 => ::private::cstr_to_slice(buf as _).len() as _,
				r => r,
			}})
	}
}

/*
TODO
x509write_crt_set_version
x509write_crt_set_ns_cert_type
x509write_crt_set_authority_key_identifier
x509write_crt_set_subject_key_identifier
*/

#[cfg(test)]
mod tests {
	use super::*;
	use pk::Pk;
	
	struct Test {
		key1: Pk,
		key2: Pk,
	}
	
	impl Test {
		fn new() -> Self {
			Test{
				key1:Pk::from_private_key(::test_support::keys::PEM_KEY,None).unwrap(),
				key2:Pk::from_private_key(::test_support::keys::PEM_KEY,None).unwrap(),
			}
		}
		
		fn builder<'a>(&'a mut self) -> Builder<'a> {
			use x509::Time;
			
			let mut b=Builder::new();
			b.subject_key(&mut self.key1)
			 .subject_with_nul("CN=mbedtls.example\0").unwrap()
			 .issuer_key(&mut self.key2)
			 .issuer_with_nul("CN=mbedtls.example\0").unwrap()
			 .validity(Time::new(2000,1,1,0,0,0).unwrap(),Time::new(2009,12,31,23,59,59).unwrap()).unwrap();
			b
		}
	}
	
	const TEST_PEM: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIICsDCCAZigAwIBAgIAMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMTD21iZWR0
bHMuZXhhbXBsZTAeFw0wMDAxMDEwMDAwMDBaFw0wOTEyMzEyMzU5NTlaMBoxGDAW
BgNVBAMTD21iZWR0bHMuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMWMCCYIlSYoBD84CDQwGHcTb6XlqxId0E2ZObSCve+aeYVxSqUilQbc
EZ3zmjRz1fmqfEEolp9Mku7bFGqPHVMyUF21Wk/QJfLmo9jC87xRYgbKuyeLLwZ+
kONcaRQVub3ULDVz+UIPtHXqUscr7s2mr2jGmTcp8weK9CisV3fVvKjRXFm/+wVh
WIJsO05iYyJ9Bf+qSqxu+TFK4+SXOnEDEXzbia0oxGKbAZBtni1suUAU26A7TZ5X
QerzEfF9uY2tuVKojLrz9R2ODhj194WLw1V9iD+uwWO4v4W//d0sEGFox9/JX0nR
5QteBXDllc1pCApvqxIFCqJTct+0cNMCAwEAAaMCMAAwDQYJKoZIhvcNAQELBQAD
ggEBAHPvfmCqFRoyQATPo8aV16QC22rpHiML96QgjHP+C12U/A4cVn5Qu4GhBmte
SbMr/5C3EXtGr3HscqLkmcVu+IUd9Cj1rhAcyR6HA3OMHL17Xa6mhb8qbU1q1JVB
yj9wo3CnzOvVa5Yt1HWfKWYX3RVeSDvOaN2rrKauiVQ/KPSD9gWrySCt7Kqp+Ruk
1Ib3Ni1rpWZUjzARTRTHfIlGYWsD808njO0KtVorprsoVFRr4jmbF2rITqoCWXEs
2vgB8DVoWy57/ygyXqFYTQ2f0jqcV1SMNwn5iWlI9JvOrLd9ljmmonR2GieWTHD+
5PyXrqth5J9gUK+khH8rCeyy1Mk=
-----END CERTIFICATE-----
";

	const TEST_DER: &'static [u8] = &[0x30, 0x82, 0x02, 0xb0, 0x30, 0x82, 0x01,
		0x98, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x00, 0x30, 0x0d, 0x06, 0x09, 
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 
		0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0f, 
		0x6d, 0x62, 0x65, 0x64, 0x74, 0x6c, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 
		0x70, 0x6c, 0x65, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x30, 0x30, 0x31, 0x30, 
		0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x30, 0x39, 
		0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 
		0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0f, 
		0x6d, 0x62, 0x65, 0x64, 0x74, 0x6c, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 
		0x70, 0x6c, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 
		0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 
		0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 
		0xc5, 0x8c, 0x08, 0x26, 0x08, 0x95, 0x26, 0x28, 0x04, 0x3f, 0x38, 0x08, 
		0x34, 0x30, 0x18, 0x77, 0x13, 0x6f, 0xa5, 0xe5, 0xab, 0x12, 0x1d, 0xd0, 
		0x4d, 0x99, 0x39, 0xb4, 0x82, 0xbd, 0xef, 0x9a, 0x79, 0x85, 0x71, 0x4a, 
		0xa5, 0x22, 0x95, 0x06, 0xdc, 0x11, 0x9d, 0xf3, 0x9a, 0x34, 0x73, 0xd5, 
		0xf9, 0xaa, 0x7c, 0x41, 0x28, 0x96, 0x9f, 0x4c, 0x92, 0xee, 0xdb, 0x14, 
		0x6a, 0x8f, 0x1d, 0x53, 0x32, 0x50, 0x5d, 0xb5, 0x5a, 0x4f, 0xd0, 0x25, 
		0xf2, 0xe6, 0xa3, 0xd8, 0xc2, 0xf3, 0xbc, 0x51, 0x62, 0x06, 0xca, 0xbb, 
		0x27, 0x8b, 0x2f, 0x06, 0x7e, 0x90, 0xe3, 0x5c, 0x69, 0x14, 0x15, 0xb9, 
		0xbd, 0xd4, 0x2c, 0x35, 0x73, 0xf9, 0x42, 0x0f, 0xb4, 0x75, 0xea, 0x52, 
		0xc7, 0x2b, 0xee, 0xcd, 0xa6, 0xaf, 0x68, 0xc6, 0x99, 0x37, 0x29, 0xf3, 
		0x07, 0x8a, 0xf4, 0x28, 0xac, 0x57, 0x77, 0xd5, 0xbc, 0xa8, 0xd1, 0x5c, 
		0x59, 0xbf, 0xfb, 0x05, 0x61, 0x58, 0x82, 0x6c, 0x3b, 0x4e, 0x62, 0x63, 
		0x22, 0x7d, 0x05, 0xff, 0xaa, 0x4a, 0xac, 0x6e, 0xf9, 0x31, 0x4a, 0xe3, 
		0xe4, 0x97, 0x3a, 0x71, 0x03, 0x11, 0x7c, 0xdb, 0x89, 0xad, 0x28, 0xc4, 
		0x62, 0x9b, 0x01, 0x90, 0x6d, 0x9e, 0x2d, 0x6c, 0xb9, 0x40, 0x14, 0xdb, 
		0xa0, 0x3b, 0x4d, 0x9e, 0x57, 0x41, 0xea, 0xf3, 0x11, 0xf1, 0x7d, 0xb9, 
		0x8d, 0xad, 0xb9, 0x52, 0xa8, 0x8c, 0xba, 0xf3, 0xf5, 0x1d, 0x8e, 0x0e, 
		0x18, 0xf5, 0xf7, 0x85, 0x8b, 0xc3, 0x55, 0x7d, 0x88, 0x3f, 0xae, 0xc1, 
		0x63, 0xb8, 0xbf, 0x85, 0xbf, 0xfd, 0xdd, 0x2c, 0x10, 0x61, 0x68, 0xc7, 
		0xdf, 0xc9, 0x5f, 0x49, 0xd1, 0xe5, 0x0b, 0x5e, 0x05, 0x70, 0xe5, 0x95, 
		0xcd, 0x69, 0x08, 0x0a, 0x6f, 0xab, 0x12, 0x05, 0x0a, 0xa2, 0x53, 0x72, 
		0xdf, 0xb4, 0x70, 0xd3, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x02, 0x30, 
		0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 
		0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x73, 0xef, 0x7e, 
		0x60, 0xaa, 0x15, 0x1a, 0x32, 0x40, 0x04, 0xcf, 0xa3, 0xc6, 0x95, 0xd7, 
		0xa4, 0x02, 0xdb, 0x6a, 0xe9, 0x1e, 0x23, 0x0b, 0xf7, 0xa4, 0x20, 0x8c, 
		0x73, 0xfe, 0x0b, 0x5d, 0x94, 0xfc, 0x0e, 0x1c, 0x56, 0x7e, 0x50, 0xbb, 
		0x81, 0xa1, 0x06, 0x6b, 0x5e, 0x49, 0xb3, 0x2b, 0xff, 0x90, 0xb7, 0x11, 
		0x7b, 0x46, 0xaf, 0x71, 0xec, 0x72, 0xa2, 0xe4, 0x99, 0xc5, 0x6e, 0xf8, 
		0x85, 0x1d, 0xf4, 0x28, 0xf5, 0xae, 0x10, 0x1c, 0xc9, 0x1e, 0x87, 0x03, 
		0x73, 0x8c, 0x1c, 0xbd, 0x7b, 0x5d, 0xae, 0xa6, 0x85, 0xbf, 0x2a, 0x6d, 
		0x4d, 0x6a, 0xd4, 0x95, 0x41, 0xca, 0x3f, 0x70, 0xa3, 0x70, 0xa7, 0xcc, 
		0xeb, 0xd5, 0x6b, 0x96, 0x2d, 0xd4, 0x75, 0x9f, 0x29, 0x66, 0x17, 0xdd, 
		0x15, 0x5e, 0x48, 0x3b, 0xce, 0x68, 0xdd, 0xab, 0xac, 0xa6, 0xae, 0x89, 
		0x54, 0x3f, 0x28, 0xf4, 0x83, 0xf6, 0x05, 0xab, 0xc9, 0x20, 0xad, 0xec, 
		0xaa, 0xa9, 0xf9, 0x1b, 0xa4, 0xd4, 0x86, 0xf7, 0x36, 0x2d, 0x6b, 0xa5, 
		0x66, 0x54, 0x8f, 0x30, 0x11, 0x4d, 0x14, 0xc7, 0x7c, 0x89, 0x46, 0x61, 
		0x6b, 0x03, 0xf3, 0x4f, 0x27, 0x8c, 0xed, 0x0a, 0xb5, 0x5a, 0x2b, 0xa6, 
		0xbb, 0x28, 0x54, 0x54, 0x6b, 0xe2, 0x39, 0x9b, 0x17, 0x6a, 0xc8, 0x4e, 
		0xaa, 0x02, 0x59, 0x71, 0x2c, 0xda, 0xf8, 0x01, 0xf0, 0x35, 0x68, 0x5b, 
		0x2e, 0x7b, 0xff, 0x28, 0x32, 0x5e, 0xa1, 0x58, 0x4d, 0x0d, 0x9f, 0xd2, 
		0x3a, 0x9c, 0x57, 0x54, 0x8c, 0x37, 0x09, 0xf9, 0x89, 0x69, 0x48, 0xf4, 
		0x9b, 0xce, 0xac, 0xb7, 0x7d, 0x96, 0x39, 0xa6, 0xa2, 0x74, 0x76, 0x1a, 
		0x27, 0x96, 0x4c, 0x70, 0xfe, 0xe4, 0xfc, 0x97, 0xae, 0xab, 0x61, 0xe4, 
		0x9f, 0x60, 0x50, 0xaf, 0xa4, 0x84, 0x7f, 0x2b, 0x09, 0xec, 0xb2, 0xd4, 
		0xc9];

	#[test]
	fn write_der() {
		let mut t=Test::new();
		let mut buf=[0u8;2048];
		let output=t.builder().signature_hash(::hash::Type::Sha256).write_der(&mut buf, &mut ::test_support::rand::test_rng()).unwrap().unwrap();
		assert_eq!(output,TEST_DER);
	}

	#[cfg(feature="collections")]
	#[test]
	fn write_der_vec() {
		let mut t=Test::new();
		let output=t.builder().signature_hash(::hash::Type::Sha256).write_der_vec(&mut ::test_support::rand::test_rng()).unwrap();
		assert_eq!(output,TEST_DER);
	}

	#[test]
	fn write_pem() {
		let mut t=Test::new();
		let mut buf=[0u8;2048];
		let output=t.builder().signature_hash(::hash::Type::Sha256).write_pem(&mut buf, &mut ::test_support::rand::test_rng()).unwrap().unwrap();
		assert_eq!(output,TEST_PEM);
	}

	#[cfg(feature="collections")]
	#[test]
	fn write_pem_string() {
		let mut t=Test::new();
		let output=t.builder().signature_hash(::hash::Type::Sha256).write_pem_string(&mut ::test_support::rand::test_rng()).unwrap();
		assert_eq!(output.as_bytes(),TEST_PEM);
	}
}
