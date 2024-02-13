/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use rand::{Rng, XorShiftRng};

/// Not cryptographically secure!!! Use for testing only!!!
pub struct TestInsecureRandom(XorShiftRng);

impl crate::mbedtls::rng::RngCallbackMut for TestInsecureRandom {
    unsafe extern "C" fn call_mut(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestInsecureRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self as *const _ as *mut _
    }
}

impl crate::mbedtls::rng::RngCallback for TestInsecureRandom {
    unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestInsecureRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        self as *const _ as *mut _
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(feature = "rdrand", target_env = "sgx", feature = "std"))]
    {
        pub type TestRandom = crate::mbedtls::rng::CtrDrbg;
    } else {
        pub type TestRandom = TestInsecureRandom;
    }
}

/// Not cryptographically secure!!! Use for testing only!!!
pub fn test_rng() -> TestRandom {
    cfg_if::cfg_if! {
        if #[cfg(any(feature = "rdrand", target_env = "sgx", feature = "std"))]
        {
            #[cfg(feature = "std")]
            use std::sync::Arc;
            #[cfg(not(feature = "std"))]
            extern crate alloc as rust_alloc;
            #[cfg(not(feature = "std"))]
            use rust_alloc::sync::Arc;

            let entropy = Arc::new(super::entropy::entropy_new());
            TestRandom::new(entropy, None).unwrap()
        } else {
            test_deterministic_rng()
        }
    }
}

/// Not cryptographically secure!!! Use for testing only!!!
pub fn test_deterministic_rng() -> TestInsecureRandom {
    TestInsecureRandom(XorShiftRng::new_unseeded())
}
