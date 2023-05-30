/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::ptr::drop_in_place;
use core::mem::ManuallyDrop;

use mbedtls_sys::types::raw_types::c_void;

extern "C" {
    #[link_name = concat!("forward_mbedtls_free_", env!("RUST_MBEDTLS_METADATA_HASH"))]
    pub(crate) fn mbedtls_free(n: *mut mbedtls_sys::types::raw_types::c_void);
    #[link_name = concat!("forward_mbedtls_calloc_", env!("RUST_MBEDTLS_METADATA_HASH"))]
    pub(crate) fn mbedtls_calloc(n: mbedtls_sys::types::size_t, size: mbedtls_sys::types::size_t) -> *mut mbedtls_sys::types::raw_types::c_void;
}

#[repr(transparent)]
pub struct Box<T> {
    pub(crate) inner: NonNull<T>
}

impl<T> Box<T> {
    pub(crate) fn into_raw(self) -> *mut T {
        let v = ManuallyDrop::new(self);
        v.inner.as_ptr()
    }
}

impl<T> Deref for Box<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.inner.as_ref() }
    }
}

impl<T> DerefMut for Box<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.inner.as_mut() }
    }
}

impl<T: fmt::Debug> fmt::Debug for Box<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for Box<T> {
    fn drop(&mut self) {
        unsafe {
            drop_in_place(self.inner.as_ptr());
            mbedtls_free(self.inner.as_ptr() as *mut c_void)
        }
    }
}

unsafe impl<T: Send> Send for Box<T> {}
unsafe impl<T: Sync> Sync for Box<T> {}

#[repr(transparent)]
pub struct List<T> {
    pub(crate) inner: Option<Box<T>>
}
