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
    cfg_if! {
        if #[cfg(any(
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
        ))] {
            pub type c_char = u8;
        } else {
            pub type c_char = i8;
        }
    }
    pub type c_schar = i8;
    pub type c_uchar = u8;
    pub type c_short = i16;
    pub type c_ushort = u16;
    pub type c_int = i32;
    pub type c_uint = u32;
    cfg_if! {
        if #[cfg(any(target_pointer_width = "32", windows))] {
            pub type c_long = i32;
            pub type c_ulong = u32;
        } else {
            pub type c_long = i64;
            pub type c_ulong = u64;
        }
    }
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

#[cfg(unix)]
extern crate libc;

#[cfg(std_component = "fs")]
pub use self::libc::FILE;

cfg_if! {
    if #[cfg(time_component = "custom")] {
        pub type time_t = raw_types::c_longlong;
        #[repr(C)]
        pub struct tm {
            pub tm_sec:   i32,            /* Seconds.        [0-60] (1 leap second) */
            pub tm_min:   i32,            /* Minutes.        [0-59] */
            pub tm_hour:  i32,            /* Hours.          [0-23] */
            pub tm_mday:  i32,            /* Day.            [1-31] */
            pub tm_mon:   i32,            /* Month.          [0-11] */
            pub tm_year:  i32,            /* Year          - 1900.  */
            pub tm_wday:  i32,            /* Day of week.    [0-6]  */
            pub tm_yday:  i32,            /* Days in year.   [0-365]*/
            pub tm_isdst: i32,
        }
    } else if #[cfg(time_component = "libc")] {
        pub use self::libc::{tm, time_t};
    }
}

#[cfg(threading_component = "pthread")]
pub use self::libc::pthread_mutex_t;
