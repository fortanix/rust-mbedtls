/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[doc(hidden)]
#[cfg(any(feature = "spin_threading", feature = "rust_threading"))]
#[cfg(sys_threading_component = "custom")]
// needs to be pub for global visiblity
pub mod threading;

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visiblity
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
    return 1;
}

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visiblity
pub extern "C" fn mbedtls_internal_aes_encrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                _input: *const u8,
                                                _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}

#[cfg(any(feature = "force_aesni_support", target_env = "sgx"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visiblity
pub extern "C" fn mbedtls_internal_aes_decrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                _input: *const u8,
                                                _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}


#[cfg(sys_time_component = "custom")]
// following cfg is for backward compatible with mbedtls 0.7
#[cfg(all(feature = "time", feature = "custom_gmtime_r"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visiblity
pub unsafe extern "C" fn mbedtls_platform_gmtime_r(tt: *const mbedtls_sys::types::time_t, tp: *mut mbedtls_sys::types::tm) -> *mut mbedtls_sys::types::tm {
    use chrono::prelude::*;

    //0 means no TZ offset
    let naive = if tp.is_null() {
        return core::ptr::null_mut()
    } else {
        NaiveDateTime::from_timestamp(*tt, 0)
    };
    let utc = DateTime::<Utc>::from_utc(naive, Utc);

    let tp = &mut *tp;
    tp.tm_sec   = utc.second()   as i32;
    tp.tm_min   = utc.minute()   as i32;
    tp.tm_hour  = utc.hour()     as i32;
    tp.tm_mday  = utc.day()      as i32;
    tp.tm_mon   = utc.month0()   as i32;
    tp.tm_year  = utc.year()     as i32 - 1900;
    tp.tm_wday  = utc.weekday().num_days_from_monday() as i32;
    tp.tm_yday  = utc.ordinal0() as i32;
    tp.tm_isdst = 0;

    tp
}

#[cfg(sys_time_component = "custom")]
// following cfg is for backward compatible with mbedtls 0.7
#[cfg(all(feature = "time", feature = "custom_time"))]
#[doc(hidden)]
#[no_mangle]
// needs to be pub for global visiblity
pub unsafe extern "C" fn mbedtls_time(tp: *mut mbedtls_sys::types::time_t) -> mbedtls_sys::types::time_t {
    let timestamp = chrono::Utc::now().timestamp() as mbedtls_sys::types::time_t;
    if !tp.is_null() {
        *tp = timestamp;
    }
    timestamp
}
