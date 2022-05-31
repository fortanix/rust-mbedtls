/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(feature = "std")]
use std::sync::Arc;

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::CTR_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::error::{IntoResult, Result};
use crate::rng::{EntropyCallback, EntropyCallbackMut, RngCallback, RngCallbackMut};

enum EntropyHolder {
    Shared(Arc<dyn EntropyCallback + 'static>),
    Unique(Box<dyn EntropyCallbackMut + 'static>),
}

define!(
    // `ctr_drbg_context` inlines an `aes_context`, which is immovable. See
    // https://github.com/ARMmbed/mbedtls/issues/2147. We work around this
    // by always boxing up the context, which requires this module to depend on
    // std/alloc.
    //
    // If `ctr_drbg_context` were moveable we could use c_ty instead of c_box_ty.
    //
    #[c_box_ty(ctr_drbg_context)]
    #[repr(C)]
    struct CtrDrbg {
        entropy: EntropyHolder,
    };
    const drop: fn(&mut Self) = ctr_drbg_free;
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
unsafe impl Sync for CtrDrbg {}

#[allow(dead_code)]
impl CtrDrbg {
    pub fn new<T: EntropyCallback + 'static>(
        entropy: Arc<T>,
        additional_entropy: Option<&[u8]>,
    ) -> Result<Self> {
        let mut inner = Box::new(ctr_drbg_context::default());

        unsafe {
            ctr_drbg_init(&mut *inner);
            ctr_drbg_seed(
                &mut *inner,
                Some(T::call),
                entropy.data_ptr(),
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0),
            )
            .into_result()?;
        }

        Ok(CtrDrbg {
            inner,
            entropy: EntropyHolder::Shared(entropy),
        })
    }

    pub fn with_mut_entropy<T: EntropyCallbackMut + 'static>(
        entropy: T,
        additional_entropy: Option<&[u8]>,
    ) -> Result<Self> {
        let mut inner = Box::new(ctr_drbg_context::default());

        // We take sole ownership of entropy, all access is guarded via mutexes.
        let mut entropy = Box::new(entropy);
        unsafe {
            ctr_drbg_init(&mut *inner);
            ctr_drbg_seed(
                &mut *inner,
                Some(T::call_mut),
                entropy.data_ptr_mut(),
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0),
            )
            .into_result()?;
        }

        Ok(CtrDrbg {
            inner,
            entropy: EntropyHolder::Unique(entropy),
        })
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == CTR_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            ctr_drbg_set_prediction_resistance(
                &mut *self.inner,
                if pr { CTR_DRBG_PR_ON } else { CTR_DRBG_PR_OFF },
            )
        }
    }

    getter!(entropy_len() -> size_t = .entropy_len);
    setter!(set_entropy_len(len: size_t) = ctr_drbg_set_entropy_len);
    getter!(reseed_interval() -> c_int = .reseed_interval);
    setter!(set_reseed_interval(i: c_int) = ctr_drbg_set_reseed_interval);

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            ctr_drbg_reseed(
                &mut *self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0),
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { ctr_drbg_update(&mut *self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // ctr_drbg_random_with_add
    // ctr_drbg_write_seed_file
    // ctr_drbg_update_seed_file
    //
}

impl RngCallbackMut for CtrDrbg {
    #[inline(always)]
    unsafe extern "C" fn call_mut(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int
    where
        Self: Sized,
    {
        // Mutex used in ctr_drbg_random at: ../../../mbedtls-sys/vendor/crypto/library/ctr_drbg.c:546
        ctr_drbg_random(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self.handle_mut() as *const _ as *mut _
    }
}

impl RngCallback for CtrDrbg {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int
    where
        Self: Sized,
    {
        // Mutex used in ctr_drbg_random at: ../../../mbedtls-sys/vendor/crypto/library/ctr_drbg.c:546
        ctr_drbg_random(user_data, data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        self.handle() as *const _ as *mut _
    }
}
