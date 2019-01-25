/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(non_camel_case_types)]

pub type int8_t = i8;
pub type int16_t = i16;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type uint64_t = u64;
pub type size_t = usize;
pub type ssize_t = isize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ptrdiff_t = isize;

#[cfg(feature = "std")]
pub use std::os::raw as raw_types;

#[cfg(not(feature = "std"))]
pub mod raw_types {
    // From libstd/os/raw.rs
    #[cfg(any(
        target_os = "android",
        target_os = "emscripten",
        all(
            target_os = "linux",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        )
    ))]
    pub type c_char = u8;
    #[cfg(not(any(
        target_os = "android",
        target_os = "emscripten",
        all(
            target_os = "linux",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        )
    )))]
    pub type c_char = i8;
    pub type c_schar = i8;
    pub type c_uchar = u8;
    pub type c_short = i16;
    pub type c_ushort = u16;
    pub type c_int = i32;
    pub type c_uint = u32;
    #[cfg(any(target_pointer_width = "32", windows))]
    pub type c_long = i32;
    #[cfg(any(target_pointer_width = "32", windows))]
    pub type c_ulong = u32;
    #[cfg(all(target_pointer_width = "64", not(windows)))]
    pub type c_long = i64;
    #[cfg(all(target_pointer_width = "64", not(windows)))]
    pub type c_ulong = u64;
    pub type c_longlong = i64;
    pub type c_ulonglong = u64;
    pub type c_float = f32;
    pub type c_double = f64;

    #[repr(u8)]
    pub enum c_void {
        #[doc(hidden)]
        __variant1,
        #[doc(hidden)]
        __variant2,
    }
}

#[cfg(feature = "libc")]
extern crate libc;
#[cfg(feature = "libc")]
mod libc_types {
    pub use super::libc::FILE;
}

#[cfg(not(feature = "libc"))]
mod libc_types {
    pub enum FILE {}
}

pub use self::libc_types::*;

#[cfg(feature = "pthread")]
pub use self::libc::pthread_mutex_t;

#[cfg(feature = "time")]
pub use self::libc::{time_t, tm};

#[cfg(feature = "zlib")]
extern crate libz_sys;
#[cfg(feature = "zlib")]
pub use self::libz_sys::z_stream;

#[cfg(feature = "pkcs11")]
const ERROR: _PKCS11_NOT_SUPPORTED_ = ();
