/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[allow(unused)]
#[macro_use]
extern crate alloc as rust_alloc;

#[cfg(not(feature = "std"))]
mod alloc_prelude {
    #![allow(unused)]
    pub(crate) use rust_alloc::borrow::ToOwned;
    pub(crate) use rust_alloc::boxed::Box;
    pub(crate) use rust_alloc::sync::Arc;
    pub(crate) use rust_alloc::string::String;
    pub(crate) use rust_alloc::string::ToString;
    pub(crate) use rust_alloc::vec::Vec;
    pub(crate) use rust_alloc::borrow::Cow;
}

pub mod self_test;

#[cfg(any(feature = "spin_threading", feature = "rust_threading", sys_threading_component = "custom"))]
#[doc(hidden)]
pub mod threading;

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
    return 1;
}

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub extern "C" fn mbedtls_internal_aes_encrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                _input: *const u8,
                                                _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub extern "C" fn mbedtls_internal_aes_decrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                _input: *const u8,
                                                _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}


#[cfg(any(all(feature = "time", feature = "custom_gmtime_r"), sys_time_component = "custom"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub unsafe extern "C" fn mbedtls_platform_gmtime_r(tt: *const mbedtls_sys::types::time_t, tp: *mut mbedtls_sys::types::tm) -> *mut mbedtls_sys::types::tm {
    use chrono::prelude::*;

    //0 means no TZ offset
    let naive = if tp.is_null() {
        return core::ptr::null_mut()
    } else {
        match NaiveDateTime::from_timestamp_opt(*tt, 0) {
            Some(t) => t,
            None => return core::ptr::null_mut()
        }
    };
    let utc = DateTime::<Utc>::from_utc(naive, Utc);

    let tp = &mut *tp;
    tp.tm_sec   = utc.second()   as i32;
    tp.tm_min   = utc.minute()   as i32;
    tp.tm_hour  = utc.hour()     as i32;
    tp.tm_mday  = utc.day()      as i32;
    tp.tm_mon   = utc.month0()   as i32;
    tp.tm_year  = match (utc.year() as i32).checked_sub(1900) {
        Some(year) => year,
        None => return core::ptr::null_mut()
    };
    tp.tm_wday  = utc.weekday().num_days_from_sunday() as i32;
    tp.tm_yday  = utc.ordinal0() as i32;
    tp.tm_isdst = 0;

    tp
}

#[cfg(any(all(feature = "time", feature = "custom_time"), sys_time_component = "custom"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub unsafe extern "C" fn mbedtls_time(tp: *mut mbedtls_sys::types::time_t) -> mbedtls_sys::types::time_t {
    let timestamp = chrono::Utc::now().timestamp() as mbedtls_sys::types::time_t;
    if !tp.is_null() {
        *tp = timestamp;
    }
    timestamp
}

#[cfg(all(any(feature = "time", sys_time_component = "custom"), not(feature = "std")))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub unsafe extern "C" fn mbedtls_ms_time() -> mbedtls_sys::types::int64_t {
    chrono::Utc::now().timestamp_millis() as mbedtls_sys::types::int64_t
}

#[cfg(target_env = "sgx")]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visibility
pub unsafe extern "C" fn explicit_bzero(buf: *mut mbedtls_sys::types::raw_types::c_void, len: mbedtls_sys::types::size_t)  {
    use zeroize::Zeroize;
    let buffer = core::slice::from_raw_parts_mut(buf as *mut mbedtls_sys::types::raw_types::c_char, len);
    buffer.zeroize();
}