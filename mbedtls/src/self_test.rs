/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

//! MbedTLS self tests.
//!
//! Calling MbedTLS self test functions before they're enabled using the
//! `enable()` function here will result in a panic.
//!
//! Using this module in multithreaded or async environment will fail. The self
//! test functions rely on global variables to track operations and anything
//! non-self-test related operations will clobber these variables, resulting in
//! self test failures. Make sure no other code uses MbedTLS while running the
//! self tests. Multiple self test operations done simultaneously may also
//! return failures.

use mbedtls_sys::types::raw_types::{c_char, c_int};

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_log(msg: *const std::os::raw::c_char) {
            print!("{}", std::ffi::CStr::from_ptr(msg).to_string_lossy());
        }
    } else {
        #[allow(non_upper_case_globals)]
        static mut log_f: Option<unsafe fn(*const c_char)> = None;

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_log(msg: *const c_char) {
            log_f.expect("Called self-test log without enabling self-test")(msg)
        }
    }
}
cfg_if::cfg_if! {
    if #[cfg(any(not(feature = "std"), target_env = "sgx"))] {
        #[allow(non_upper_case_globals)]
        static mut rand_f: Option<fn() -> c_int> = None;

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn rand() -> c_int {
            rand_f.expect("Called self-test rand without enabling self-test")()
        }
    }
}

/// Set callback functions to enable the MbedTLS self tests.
///
/// `rand` only needs to be set on platforms that don't have a `rand()`
/// function in libc. `log` only needs to be set when using `no_std`, i.e.
/// the `std` feature of this create is not enabled. If neither function
/// needs to be set, you don't have to call `enable()`.
///
/// # Safety
///
/// The caller needs to ensure this function is not called while any other
/// function in this module is called.
#[allow(unused)]
pub unsafe fn enable(rand: fn() -> c_int, log: Option<unsafe fn(*const c_char)>) {
    #[cfg(any(not(feature = "std"), target_env = "sgx"))] {
        rand_f = Some(rand);
    }
    #[cfg(not(feature = "std"))] {
        log_f = log;
    }
}

/// # Safety
///
/// The caller needs to ensure this function is not called while any other
/// function in this module is called.
pub unsafe fn disable() {
    #[cfg(any(not(feature = "std"), target_env = "sgx"))] {
        rand_f = None;
    }
    #[cfg(not(feature = "std"))] {
        log_f = None;
    }
}

/// # Safety
///
/// The caller needs to ensure this function is not called while *any other*
/// MbedTLS function is called. See the module documentation for more
/// information.
pub use mbedtls_sys::{
    aes_self_test as aes,
    aria_self_test as aria,
    base64_self_test as base64,
    camellia_self_test as camellia,
    ccm_self_test as ccm,
    chacha20_self_test as chacha20,
    chachapoly_self_test as chachapoly,
    cmac_self_test as cmac,
    ctr_drbg_self_test as ctr_drbg,
    des_self_test as des,
    dhm_self_test as dhm,
    ecjpake_self_test as ecjpake,
    ecp_self_test as ecp,
    entropy_self_test as entropy,
    gcm_self_test as gcm,
    hmac_drbg_self_test as hmac_drbg,
    md5_self_test as md5,
    memory_buffer_alloc_self_test as memory_buffer_alloc,
    mpi_self_test as mpi,
    nist_kw_self_test as nist_kw,
    pkcs5_self_test as pkcs5,
    poly1305_self_test as poly1305,
    ripemd160_self_test as ripemd160,
    rsa_self_test as rsa,
    sha1_self_test as sha1,
    sha256_self_test as sha256,
    sha512_self_test as sha512,
};
