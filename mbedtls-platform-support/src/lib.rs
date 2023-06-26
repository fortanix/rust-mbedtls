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

/// You need to call `psa_crypto_init()` before calling any function from the SSL/TLS, X.509 or PK modules.
/// This function is fine to be called mutiple times while ensure underlying initilization function is only
/// been called only once.
/// Although this function is documented to be safely called multiple times, it still throws error in muti-thread case.
/// Upstream document: https://arm-software.github.io/psa-api/crypto/1.1/api/library/library.html#c.psa_crypto_init
/// See tracking issue: https://github.com/fortanix/rust-mbedtls/issues/285
#[cfg(feature = "tls13")]
pub fn psa_crypto_init() {
    use once_cell::sync::OnceCell;
    static INIT: OnceCell<()> = OnceCell::new();

    INIT.get_or_init(|| {
        unsafe { mbedtls_sys::psa::crypto_init() };
        return ();
    });
}

/// An implementation of an external random generator need to provided for Mbed TLS's PSA module when there is no RNG provided by platform, e.g. libc.
/// This feature replaces the RNG calls in Mbed TLS's PSA module when enabled.
///
/// # Safety
/// This function is marked `unsafe` as it's a function exposed to C to use.
///
///
/// # Return
/// This function returns zero on success or ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED if it cannot generate random data.
///
/// # Notes
/// * This function uses the hardware `RDRAND` instruction, if available (x86 only), as a source of randomness.
#[cfg(sys_tls13_component = "external_entropy")]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_psa_external_get_random(
    _user_data: *mut mbedtls_sys::types::raw_types::c_void,
    data: *mut mbedtls_sys::types::raw_types::c_uchar,
    len: mbedtls_sys::types::size_t,
    olen: *mut mbedtls_sys::types::size_t,
) -> mbedtls_sys::types::int32_t {
    // Intel documentation claims that if hardware is working RDRAND will produce
    // output after at most 10 attempts
    const RDRAND_READ_ATTEMPTS: usize = 10;

    #[cfg(target_arch = "x86")]
    use core::arch::x86_64::_rdrand32_step as rdrand_step;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::_rdrand64_step as rdrand_step;

    fn call_cpu_rng<T, F>(attempts: usize, intrin: unsafe fn(&mut T) -> i32, cast: F) -> Option<usize>
    where
        T: Sized + Default,
        F: FnOnce(T) -> usize,
    {
        assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<usize>());

        for _ in 0..attempts {
            let mut out = T::default();
            let status = unsafe { intrin(&mut out) };
            if status == 1 {
                return Some(cast(out));
            }
        }
        None
    }

    // outbuf data/len are stack variables
    let mut outbuf = core::slice::from_raw_parts_mut(data, len);

    // rdrand function is thread safe
    let stepsize = core::mem::size_of::<usize>();

    for chunk in (&mut outbuf).chunks_mut(stepsize) {
        if let Some(val) = call_cpu_rng(RDRAND_READ_ATTEMPTS, rdrand_step, |x| x as usize) {
            let buf = val.to_ne_bytes();
            let ptr = &buf[..chunk.len()];
            chunk.copy_from_slice(ptr);
        } else {
            return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
        }
    }
    *olen = len;
    0
}
