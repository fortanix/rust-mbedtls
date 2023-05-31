/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */


extern crate mbedtls;
use mbedtls::{Error, codes, error::HiError, error::LoError};


#[test]
fn test_common_error_ops() {
    let (hi, lo) = (codes::CipherAllocFailed, codes::AesBadInputData);
    let (hi_only_error, lo_only_error, combined_error) = (Error::HighLevel(hi), Error::LowLevel(lo), Error::HighAndLowLevel(hi, lo));
    assert_eq!(combined_error.high_level().unwrap(), hi);
    assert_eq!(combined_error.low_level().unwrap(), lo);
    assert_eq!(hi_only_error.to_int(), -24960);
    assert_eq!(lo_only_error.to_int(), -33);
    assert_eq!(combined_error.to_int(), hi_only_error.to_int() + lo_only_error.to_int());
    assert_eq!(codes::CipherAllocFailed | codes::AesBadInputData, combined_error);
    assert_eq!(codes::AesBadInputData | codes::CipherAllocFailed, combined_error);
}

#[test]
fn test_error_display() {
    let (hi, lo) = (HiError::CipherAllocFailed, LoError::AesBadInputData);
    let (hi_only_error, lo_only_error, combined_error) = (Error::HighLevel(hi), Error::LowLevel(lo), Error::HighAndLowLevel(hi, lo));
    assert_eq!(format!("{}", hi_only_error), "mbedTLS error HiError :: CipherAllocFailed");
    assert_eq!(format!("{}", lo_only_error), "mbedTLS error LoError :: AesBadInputData");
    assert_eq!(format!("{}", combined_error), "(mbedTLS error HiError :: CipherAllocFailed, mbedTLS error LoError :: AesBadInputData)");
}

#[test]
fn test_error_from_int() {
    // positive error code
    assert_eq!(Error::from(0), Error::Other(0));
    assert_eq!(Error::from(1), Error::Other(1));
    // Lo, Hi, HiAndLo cases
    assert_eq!(Error::from(-1), Error::LowLevel(LoError::Unknown(-1)));
    assert_eq!(Error::from(-0x80), Error::HighLevel(HiError::Unknown(-0x80)));
    assert_eq!(Error::from(-0x81), Error::HighAndLowLevel(HiError::Unknown(-0x80), LoError::Unknown(-1)));
    assert_eq!(Error::from(-24993), Error::HighAndLowLevel(HiError::CipherAllocFailed, LoError::AesBadInputData));
    assert_eq!(Error::from(-24960), Error::HighLevel(HiError::CipherAllocFailed));
    assert_eq!(Error::from(-33), Error::LowLevel(LoError::AesBadInputData ));
    // error code out of boundaries
    assert_eq!(Error::from(-0x01FFFF), Error::Other(-0x01FFFF));
}

#[test]
fn test_combined_error_from_mbedtls() {
    let err = mbedtls::x509::Certificate::from_der(&b"\x30\x02\x05\x00"[..]).unwrap_err();
    assert_eq!(err, Error::HighAndLowLevel(HiError::X509InvalidFormat, LoError::Asn1UnexpectedTag));
}