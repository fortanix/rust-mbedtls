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
pub mod error;
pub use crate::error::{Error, Result};

pub mod cipher;
pub mod ecp;
pub mod hash;
pub mod pk;
pub mod rng;
pub use mbedtls_platform_support::self_test as self_test;
pub mod ssl;
pub mod x509;
pub mod alloc;

#[cfg(feature = "pkcs12")]
pub mod pkcs12;

// ==============
//    Utility
// ==============
mod private;

// needs to be pub for global visibility
#[doc(hidden)]
#[cfg(sys_threading_component = "custom")]
pub mod threading;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "force_aesni_support", target_env = "sgx"))] {
        // needs to be pub for global visibility
        #[doc(hidden)]
        pub use mbedtls_platform_support::mbedtls_aesni_has_support;

        // needs to be pub for global visibility
        #[doc(hidden)]
        pub use mbedtls_platform_support::mbedtls_internal_aes_encrypt;

        // needs to be pub for global visibility
        #[doc(hidden)]
        pub use mbedtls_platform_support::mbedtls_internal_aes_decrypt;
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

cfg_if::cfg_if! {
    if #[cfg(sys_time_component = "custom")] {

        // needs to be pub for global visibility
        #[doc(hidden)]
        pub use mbedtls_platform_support::mbedtls_platform_gmtime_r;

        // needs to be pub for global visibility
        #[doc(hidden)]
        pub use mbedtls_platform_support::mbedtls_time;
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
