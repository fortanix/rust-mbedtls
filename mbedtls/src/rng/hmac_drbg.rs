/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */


#[cfg(feature = "std")]
use std::sync::Arc;

pub use mbedtls_sys::HMAC_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::error::{IntoResult, Result};
use crate::hash::MdInfo;
use crate::rng::{EntropyCallback, RngCallback, RngCallbackMut};

define!(
    #[c_ty(hmac_drbg_context)]
    struct HmacDrbg {
        entropy: Option<Arc<dyn EntropyCallback + 'static>>,
    };
    const drop: fn(&mut Self) = hmac_drbg_free;
    impl<'a> Into<ptr> {}
);

unsafe impl Sync for HmacDrbg {}

impl HmacDrbg {
    pub fn new<T: EntropyCallback + 'static>(
        md_info: MdInfo,
        entropy: Arc<T>,
        additional_entropy: Option<&[u8]>,
    ) -> Result<HmacDrbg> {

        let mut ret = HmacDrbg {
            inner: hmac_drbg_context::default(),
            entropy: Some(entropy),
        };
        
        unsafe {
            hmac_drbg_init(&mut ret.inner);
            hmac_drbg_seed(
                &mut ret.inner,
                md_info.into(),
                Some(T::call),
                ret.entropy.as_ref().unwrap().data_ptr(),
                additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(ret)
    }

    
    pub fn from_buf(md_info: MdInfo, entropy: &[u8]) -> Result<HmacDrbg> {
        let mut ret = HmacDrbg {
            inner: hmac_drbg_context::default(),
            entropy: None,
        };

        unsafe {
            hmac_drbg_init(&mut ret.inner);
            hmac_drbg_seed_buf(
                &mut ret.inner,
                md_info.into(),
                entropy.as_ptr(),
                entropy.len()
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.private_prediction_resistance == HMAC_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            hmac_drbg_set_prediction_resistance(
                &mut self.inner,
                if pr {
                    HMAC_DRBG_PR_ON
                } else {
                    HMAC_DRBG_PR_OFF
                },
            )
        }
    }

    getter!(entropy_len() -> size_t = .private_entropy_len);
    setter!(set_entropy_len(len: size_t) = hmac_drbg_set_entropy_len);
    getter!(reseed_interval() -> c_int = .private_reseed_interval);
    setter!(set_reseed_interval(i: c_int) = hmac_drbg_set_reseed_interval);

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            hmac_drbg_reseed(
                &mut self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { hmac_drbg_update(&mut self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // hmac_drbg_random_with_add
    // hmac_drbg_write_seed_file
    // hmac_drbg_update_seed_file
    //
}

impl RngCallbackMut for HmacDrbg {
    #[inline(always)]
    unsafe extern "C" fn call_mut(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self.handle_mut() as *const _ as *mut _
    }
}

impl RngCallback for HmacDrbg {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // Mutex used in hmac_drbg_random: ../../../mbedtls-sys/vendor/crypto/library/hmac_drbg.c:363
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        self.handle() as *const _ as *mut _
    }
}
