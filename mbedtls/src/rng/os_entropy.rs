/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::sync::Arc;

use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use crate::error::{IntoResult, Result};
use crate::rng::{EntropyCallback,EntropyCallbackMut};

callback!(EntropySourceCallbackMut,EntropySourceCallback(data: *mut c_uchar, size: size_t, out: *mut size_t) -> c_int);

define!(
    #[c_ty(entropy_context)]
    #[repr(C)]
    struct OsEntropy {
        sources: Vec<Arc<dyn EntropySourceCallback + 'static>>,
    };
    pub const new: fn() -> Self = entropy_init { sources: Vec::with_capacity(1), };
    const drop: fn(&mut Self) = entropy_free;
    impl<'a> Into<ptr> {}
);

//
// Class has interior mutability via function called 'call'.
// That function has an internal mutex to guarantee thread safety.
//
// The other potential conflict is a mutable reference changing class.
// That is avoided by having any users of the callback hold an 'Arc' to this class.
// Rust will then ensure that a mutable reference cannot be aquired if more then 1 Arc exists to the same class.
//
#[cfg(feature = "threading")]
unsafe impl Sync for OsEntropy {}

#[allow(dead_code)]
impl OsEntropy {
    pub fn add_source<F: EntropySourceCallback + 'static>(
        &mut self,
        source: Arc<F>,
        threshold: size_t,
        strong: bool,
    ) -> Result<()> {
        unsafe {
            // add_source is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:143
            // all sources are called at later points via 'entropy_gather_internal' which in turn is called with internal mutex locked.
            entropy_add_source(
                self.inner_ffi_mut(),
                Some(F::call),
                source.data_ptr(),
                threshold,
                if strong { ENTROPY_SOURCE_STRONG } else { ENTROPY_SOURCE_WEAK }
            )
            .into_result()?
        };

        // Rust ensures only one mutable reference is currently in use.
        self.sources.push(source);
        Ok(())
    }

    pub fn gather(&self) -> Result<()> {
        // function is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:310
        unsafe { entropy_gather(self.inner_ffi_mut()) }.into_result()?;
        Ok(())
    }

    pub fn update_manual(&self, data: &[u8]) -> Result<()> {
        // function is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:241
        unsafe { entropy_update_manual(self.inner_ffi_mut(), data.as_ptr(), data.len()) }.into_result()?;
        Ok(())
    }


    // TODO
    // entropy_write_seed_file
    // entropy_update_seed_file
    //
}

impl EntropyCallback for OsEntropy {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // mutex used in entropy_func: ../../../mbedtls-sys/vendor/crypto/library/entropy.c:348
        // note: we're not using MBEDTLS_ENTROPY_NV_SEED so the initialization is not present or a race condition.
        entropy_func(user_data, data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        &self.inner as *const _ as *mut _
    }
}

impl EntropyCallbackMut for OsEntropy {
    #[inline(always)]
    unsafe extern "C" fn call_mut(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // mutex used in entropy_func: ../../../mbedtls-sys/vendor/crypto/library/entropy.c:348
        // note: we're not using MBEDTLS_ENTROPY_NV_SEED so the initialization is not present or a race condition.
        entropy_func(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        &self.inner as *const _ as *mut _
    }
}
