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

pub mod certificate;
mod crl;
pub mod csr;
pub mod profile;

#[doc(inline)]
pub use self::certificate::{Certificate,LinkedCertificate};
pub use self::crl::Crl;
#[doc(inline)]
pub use self::csr::Csr;
#[doc(inline)]
pub use self::profile::Profile;

pub mod key_usage {
	use mbedtls_sys::types::raw_types::c_uint;
	use mbedtls_sys::*;
	
	bitflags! {
		pub flags KeyUsage: c_uint {
			const DIGITAL_SIGNATURE  = X509_KU_DIGITAL_SIGNATURE as c_uint,
			const NON_REPUDIATION    = X509_KU_NON_REPUDIATION as c_uint,
			const KEY_ENCIPHERMENT   = X509_KU_KEY_ENCIPHERMENT as c_uint,
			const DATA_ENCIPHERMENT  = X509_KU_DATA_ENCIPHERMENT as c_uint,
			const KEY_AGREEMENT      = X509_KU_KEY_AGREEMENT as c_uint,
			const KEY_CERT_SIGN      = X509_KU_KEY_CERT_SIGN as c_uint,
			const CRL_SIGN           = X509_KU_CRL_SIGN as c_uint,
			const ENCIPHER_ONLY      = X509_KU_ENCIPHER_ONLY as c_uint,
			const DECIPHER_ONLY      = X509_KU_DECIPHER_ONLY as c_uint,
		}
	}
}
#[doc(inline)]
pub use self::key_usage::KeyUsage;

/// A specific moment in time in UTC
pub struct Time {
	year: u16,
	month: u8,
	day: u8,
	hour: u8,
	minute: u8,
	second: u8,
}

use core::fmt::{self,Write as FmtWrite};

struct TimeWriter {
	buf: [u8;15],
	idx: usize,
}

impl fmt::Write for TimeWriter {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
		for (dst,src) in self.buf.iter_mut().skip(self.idx).zip(s.as_bytes().iter()) {
			*dst=*src
		};
		self.idx+=s.len();
		Ok(())
	}

    fn write_char(&mut self, c: char) -> Result<(), fmt::Error> {
		if c>='0' || c<='9' {
			if let Some(dst)=self.buf.get_mut(self.idx) {
				*dst=c as u8;
				self.idx+=1;
				return Ok(())
			}
		}
		Err(fmt::Error)
	}
}

impl Time {
	pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Time> {
		if year<10000 && month>=1 && month<=12 && day>=1 && day<=31 && hour<24 && minute<60 && second<60 {
			Some(Time{year:year,month:month,day:day,hour:hour,minute:minute,second:second})
		} else {
			None
		}
	}
	
	fn to_x509_time(&self) -> [u8;15] {
		let mut writer=TimeWriter{buf:[0;15],idx:0};
		write!(writer,"{:04}{:02}{:02}{:02}{:02}{:02}",self.year,self.month,self.day,self.hour,self.minute,self.second).expect("error formatting time");
		assert!(writer.idx==14);
		writer.buf
	}
}
