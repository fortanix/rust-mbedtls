/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::ptr::drop_in_place;
use core::ptr::NonNull;
use cstr_core::CStr;

use mbedtls_sys::types::raw_types::{c_char, c_void};

extern "C" {
    #[link_name = concat!("forward_mbedtls_free_", env!("RUST_MBEDTLS_METADATA_HASH"))]
    pub(crate) fn mbedtls_free(n: *mut mbedtls_sys::types::raw_types::c_void);
    #[link_name = concat!("forward_mbedtls_calloc_", env!("RUST_MBEDTLS_METADATA_HASH"))]
    pub(crate) fn mbedtls_calloc(
        n: mbedtls_sys::types::size_t,
        size: mbedtls_sys::types::size_t,
    ) -> *mut mbedtls_sys::types::raw_types::c_void;
}

#[repr(transparent)]
pub struct Box<T> {
    pub(crate) inner: NonNull<T>,
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
    pub(crate) inner: Option<Box<T>>,
}

/// Modeled after std's [`CString`](https://doc.rust-lang.org/std/ffi/struct.CString.html)
pub struct CString {
    /// Pointer to the allocated buffer
    inner: NonNull<u8>,
}

impl CString {
    pub fn new(str: &str) -> Self {
        unsafe {
            let buff = crate::alloc::mbedtls_calloc(1, str.len() + 1) as *mut u8;
            buff.copy_from(str.as_ptr(), str.len());
            *buff.add(str.len()) = 0;
            Self {
                inner: NonNull::new(buff).unwrap(),
            }
        }
    }
}

impl Drop for CString {
    fn drop(&mut self) {
        unsafe { crate::alloc::mbedtls_free(self.inner.as_ptr() as *mut c_void) }
    }
}

impl Deref for CString {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        unsafe { CStr::from_ptr(self.inner.as_ptr() as *const c_char) }
    }
}

#[test]
fn test_c_string() {
    let str = "spooky code here!";
    let c_str = CString::new(str);
    assert_eq!(str, c_str.to_str().unwrap())
}
