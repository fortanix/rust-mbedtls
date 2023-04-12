/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![deny(warnings)]
#![allow(unused_doc_comments)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "std", feature = "no_std_deps")))]
compile_error!("Either the `std` or `no_std_deps` feature needs to be enabled");

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc as rust_alloc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate serde_derive;
// required explicitly to force inclusion at link time
#[cfg(target_env = "sgx")]
extern crate rs_libc;

#[macro_use]
mod wrapper_macros;

// ==============
//      API
// ==============
pub mod bignum;
mod error;
pub use crate::error::{Error, Result};
pub mod cipher;
pub mod ecp;
pub mod hash;
pub mod pk;
pub mod rng;
pub use mbedtls_selftest as self_test;
pub mod ssl;
pub mod x509;
pub mod alloc;

#[cfg(feature = "pkcs12")]
pub mod pkcs12;

// ==============
//    Utility
// ==============
mod private;

// needs to be pub for global visiblity
#[doc(hidden)]
#[cfg(sys_threading_component = "custom")]
pub mod threading;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "force_aesni_support", target_env = "sgx"))] {
        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
            return 1;
        }

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_internal_aes_encrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                       _input: *const u8,
                                                       _output: *mut u8) -> i32 {
            panic!("AES-NI support is forced but the T-tables code was invoked")
        }

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn mbedtls_internal_aes_decrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                                       _input: *const u8,
                                                       _output: *mut u8) -> i32 {
            panic!("AES-NI support is forced but the T-tables code was invoked")
        }
    }
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod mbedtls {
    pub use super::*;
}

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

cfg_if::cfg_if! {
    if #[cfg(sys_time_component = "custom")] {
        use mbedtls_sys::types::{time_t, tm};

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_platform_gmtime_r(tt: *const time_t, tp: *mut tm) -> *mut tm {
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

        // needs to be pub for global visiblity
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn mbedtls_time(tp: *mut time_t) -> time_t {
            let timestamp = chrono::Utc::now().timestamp() as time_t;
            if !tp.is_null() {
                *tp = timestamp;
            }
            timestamp
        }
    }
}

/// # Safety
///
/// The caller must ensure no other MbedTLS code is running when calling this
/// function.
#[cfg(feature = "debug")]
pub unsafe fn set_global_debug_threshold(threshold: i32) {
    mbedtls_sys::debug_set_threshold(threshold);
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    /// Utilities for testing whether types implement certain traits.
    ///
    /// For each trait `Trait` that you want to be able to test, you should
    /// implement:
    /// ```ignore
    /// impl<T: “Trait”> Testable<dyn “Trait”> for T {}
    /// ```
    ///
    /// Then, to test whether a type `Type` implements `Trait`, call:
    /// ```ignore
    /// TestTrait::<dyn “Trait”, “Type”>::new().impls_trait()
    /// ```
    /// This returns a `bool` indicating whether the trait is implemented.
    // This relies on auto-deref to distinguish between types that do and don't
    // implement the trait.
    mod testtrait {
        use core::marker::PhantomData;

        pub struct NonImplTrait<T> {
            inner: PhantomData<T>
        }

        pub struct TestTrait<TraitObj: ?Sized, Type> {
            non_impl: NonImplTrait<Type>,
            phantom: PhantomData<*const TraitObj>,
        }

        pub trait Testable<T: ?Sized> {}

        impl<TraitObj: ?Sized, Type> TestTrait<TraitObj, Type> {
            pub fn new() -> Self {
                TestTrait { non_impl: NonImplTrait { inner: PhantomData }, phantom: PhantomData }
            }
        }

        impl<TraitObj: ?Sized, Type: Testable<TraitObj>> TestTrait<TraitObj, Type> {
            pub fn impls_trait(&self) -> bool {
                true
            }
        }

        impl<T> NonImplTrait<T> {
            pub fn impls_trait(&self) -> bool {
                false
            }
        }

        impl<TraitObj: ?Sized, Type> core::ops::Deref for TestTrait<TraitObj, Type> {
            type Target = NonImplTrait<Type>;

            fn deref(&self) -> &NonImplTrait<Type> {
                &self.non_impl
            }
        }
    }

    pub use testtrait::{TestTrait, Testable};

    impl<T: Send> Testable<dyn Send> for T {}
    impl<T: Sync> Testable<dyn Sync> for T {}
    impl<T: Send + Sync> Testable<dyn Send + Sync> for T {}
}
