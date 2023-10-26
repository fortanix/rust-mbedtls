/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub mod certificate;
mod crl;
pub mod csr;
pub mod profile;
// TODO
// write_crt
// write_csr

#[doc(inline)]
pub use self::certificate::Certificate;
pub use self::crl::Crl;
#[doc(inline)]
pub use self::csr::Csr;
#[doc(inline)]
pub use self::profile::Profile;
use crate::error::Error;
use crate::private::UnsafeFrom;

use bitflags::bitflags;
use mbedtls_sys::types::raw_types::{c_int, c_uint, c_void};
use mbedtls_sys::*;
bitflags! {
    pub struct KeyUsage: c_uint {
        const DIGITAL_SIGNATURE  = X509_KU_DIGITAL_SIGNATURE as c_uint;
        const NON_REPUDIATION    = X509_KU_NON_REPUDIATION as c_uint;
        const KEY_ENCIPHERMENT   = X509_KU_KEY_ENCIPHERMENT as c_uint;
        const DATA_ENCIPHERMENT  = X509_KU_DATA_ENCIPHERMENT as c_uint;
        const KEY_AGREEMENT      = X509_KU_KEY_AGREEMENT as c_uint;
        const KEY_CERT_SIGN      = X509_KU_KEY_CERT_SIGN as c_uint;
        const CRL_SIGN           = X509_KU_CRL_SIGN as c_uint;
        const ENCIPHER_ONLY      = X509_KU_ENCIPHER_ONLY as c_uint;
        const DECIPHER_ONLY      = X509_KU_DECIPHER_ONLY as c_uint;
    }
}

bitflags! {
    pub struct VerifyError: u32 {
        const CERT_BAD_KEY       = X509_BADCERT_BAD_KEY as u32;
        const CERT_BAD_MD        = X509_BADCERT_BAD_MD as u32;
        const CERT_BAD_PK        = X509_BADCERT_BAD_PK as u32;
        const CERT_CN_MISMATCH   = X509_BADCERT_CN_MISMATCH as u32;
        const CERT_EXPIRED       = X509_BADCERT_EXPIRED as u32;
        const CERT_EXT_KEY_USAGE = X509_BADCERT_EXT_KEY_USAGE as u32;
        const CERT_FUTURE        = X509_BADCERT_FUTURE as u32;
        const CERT_KEY_USAGE     = X509_BADCERT_KEY_USAGE as u32;
        const CERT_MISSING       = X509_BADCERT_MISSING as u32;
        const CERT_NOT_TRUSTED   = X509_BADCERT_NOT_TRUSTED as u32;
        const CERT_NS_CERT_TYPE  = X509_BADCERT_NS_CERT_TYPE as u32;
        const CERT_OTHER         = X509_BADCERT_OTHER as u32;
        const CERT_REVOKED       = X509_BADCERT_REVOKED as u32;
        const CERT_SKIP_VERIFY   = X509_BADCERT_SKIP_VERIFY as u32;
        const CRL_BAD_KEY        = X509_BADCRL_BAD_KEY as u32;
        const CRL_BAD_MD         = X509_BADCRL_BAD_MD as u32;
        const CRL_BAD_PK         = X509_BADCRL_BAD_PK as u32;
        const CRL_EXPIRED        = X509_BADCRL_EXPIRED as u32;
        const CRL_FUTURE         = X509_BADCRL_FUTURE as u32;
        const CRL_NOT_TRUSTED    = X509_BADCRL_NOT_TRUSTED as u32;
        const CUSTOM_BIT_20      = 0x10_0000;
        const CUSTOM_BIT_21      = 0x20_0000;
        const CUSTOM_BIT_22      = 0x40_0000;
        const CUSTOM_BIT_23      = 0x80_0000;
        const CUSTOM_BIT_24      = 0x100_0000;
        const CUSTOM_BIT_25      = 0x200_0000;
        const CUSTOM_BIT_26      = 0x400_0000;
        const CUSTOM_BIT_27      = 0x800_0000;
        const CUSTOM_BIT_28      = 0x1000_0000;
        const CUSTOM_BIT_29      = 0x2000_0000;
        const CUSTOM_BIT_30      = 0x4000_0000;
        const CUSTOM_BIT_31      = 0x8000_0000;
    }
}

impl VerifyError {
    pub fn error_info(&self) -> Vec<&'static str> {
        macro_rules! map {
            ( $e:expr, $v:expr, $( $variant:ident -> $msg:expr , )* ) => {{
                $(
                    if $e.contains(VerifyError::$variant) {
                        $v.push($msg);
                    }
                )*
            }}
        }
        let mut v = Vec::new();
        map! {
            self, v,
            CERT_BAD_KEY       -> "The certificate is signed with an unacceptable key (eg bad curve, RSA too short).",
            CERT_BAD_MD        -> "The certificate is signed with an unacceptable hash.",
            CERT_BAD_PK        -> "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).",
            CERT_CN_MISMATCH   -> "The certificate Common Name (CN) does not match with the expected CN.",
            CERT_EXPIRED       -> "The certificate validity has expired.",
            CERT_EXT_KEY_USAGE -> "Usage does not match the extendedKeyUsage extension.",
            CERT_FUTURE        -> "The certificate validity starts in the future.",
            CERT_KEY_USAGE     -> "Usage does not match the keyUsage extension.",
            CERT_MISSING       -> "Certificate was missing.",
            CERT_NOT_TRUSTED   -> "The certificate is not correctly signed by the trusted CA.",
            CERT_NS_CERT_TYPE  -> "Usage does not match the nsCertType extension.",
            CERT_OTHER         -> "Other reason (can be used by verify callback).",
            CERT_REVOKED       -> "The certificate has been revoked (is on a CRL).",
            CERT_SKIP_VERIFY   -> "Certificate verification was skipped.",
            CRL_BAD_KEY        -> "The CRL is signed with an unacceptable key (eg bad curve, RSA too short).",
            CRL_BAD_MD         -> "The CRL is signed with an unacceptable hash.",
            CRL_BAD_PK         -> "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).",
            CRL_EXPIRED        -> "The CRL is expired.",
            CRL_FUTURE         -> "The CRL is from the future.",
            CRL_NOT_TRUSTED    -> "The CRL is not correctly signed by the trusted CA.",
        }
        v
    }
}

callback!(VerifyCallback: Fn(&Certificate, i32, &mut VerifyError) -> Result<(), Error>);

pub(crate) unsafe extern "C" fn verify_callback<F>(
    closure: *mut c_void,
    crt: *mut x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int
where
    F: VerifyCallback + 'static,
{
    if crt.is_null() || closure.is_null() || flags.is_null() {
        return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA;
    }

    let cb = &*(closure as *const F);
    let crt: &mut Certificate = UnsafeFrom::from(crt).expect("valid certificate");

    let mut verify_error = match VerifyError::from_bits(*flags) {
        Some(ve) => ve,
        // This can only happen if mbedtls is setting flags in VerifyError that are
        // missing from our definition.
        None => return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA,
    };

    let res = cb(crt, depth, &mut verify_error);
    *flags = verify_error.bits();
    match res {
        Ok(()) => 0,
        Err(e) => e.to_int(),
    }
}

/// A specific moment in time in UTC
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Time {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

use core::fmt::{self, Write as FmtWrite};

struct TimeWriter {
    buf: [u8; 15],
    idx: usize,
}

impl fmt::Write for TimeWriter {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        for (dst, src) in self.buf.iter_mut().skip(self.idx).zip(s.as_bytes().iter()) {
            *dst = *src
        }
        self.idx += s.len();
        Ok(())
    }

    fn write_char(&mut self, c: char) -> Result<(), fmt::Error> {
        if c >= '0' || c <= '9' {
            if let Some(dst) = self.buf.get_mut(self.idx) {
                *dst = c as u8;
                self.idx += 1;
                return Ok(());
            }
        }
        Err(fmt::Error)
    }
}

impl Time {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Time> {
        if year < 10000 && month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour < 24 && minute < 60 && second < 60 {
            Some(Time {
                year,
                month,
                day,
                hour,
                minute,
                second,
            })
        } else {
            None
        }
    }

    pub fn to_x509_time(&self) -> [u8; 15] {
        let mut writer = TimeWriter { buf: [0; 15], idx: 0 };
        write!(
            writer,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
        .expect("error formatting time");
        assert!(writer.idx == 14);
        writer.buf
    }

    pub fn year(&self) -> u16 {
        self.year
    }
    pub fn month(&self) -> u8 {
        self.month
    }
    pub fn day(&self) -> u8 {
        self.day
    }
    pub fn hour(&self) -> u8 {
        self.hour
    }
    pub fn minute(&self) -> u8 {
        self.minute
    }
    pub fn second(&self) -> u8 {
        self.second
    }
}

#[cfg(feature = "chrono")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct InvalidTimeError;

#[cfg(feature = "chrono")]
mod chrono_time {
    use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike};
    use core::convert::{TryFrom, TryInto};

    use super::{InvalidTimeError, Time};

    impl TryFrom<Time> for NaiveDateTime {
        type Error = InvalidTimeError;

        fn try_from(value: Time) -> Result<Self, Self::Error> {
            let res = NaiveDate::from_ymd_opt(value.year.into(), value.month.into(), value.day.into())
                .and_then(|date| date.and_hms_opt(value.hour.into(), value.minute.into(), value.second.into()))
                .ok_or(InvalidTimeError)?;
            Ok(res)
        }
    }

    impl TryFrom<NaiveDateTime> for Time {
        type Error = InvalidTimeError;

        fn try_from(value: NaiveDateTime) -> Result<Self, Self::Error> {
            let res = Time::new(
                value.year().try_into().map_err(|_| InvalidTimeError)?,
                value.month().try_into().map_err(|_| InvalidTimeError)?,
                value.day().try_into().map_err(|_| InvalidTimeError)?,
                value.hour().try_into().map_err(|_| InvalidTimeError)?,
                value.minute().try_into().map_err(|_| InvalidTimeError)?,
                value.second().try_into().map_err(|_| InvalidTimeError)?,
            );
            res.ok_or(InvalidTimeError)
        }
    }

    #[test]
    fn time_naive_date_time_conversion() {
        let time = Time::new(2077, 12, 13, 10, 20, 30).unwrap();
        let naive_date_time: NaiveDateTime = time.try_into().unwrap();

        let expected = NaiveDate::from_ymd_opt(2077, 12, 13)
            .unwrap()
            .and_hms_opt(10, 20, 30)
            .unwrap();
        assert_eq!(naive_date_time, expected);

        assert_eq!(time, Time::try_from(naive_date_time).unwrap());
    }
}
