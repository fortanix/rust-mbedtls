/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::slice::from_raw_parts_mut;

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

#[cfg(target_arch = "aarch64")]
use aarch64_rdrand::{_rdrand_step, _rdseed_step};
#[cfg(target_arch = "x86")]
use core::arch::x86_64::{_rdrand32_step as _rdrand_step, _rdseed32_step as _rdseed_step};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{_rdrand64_step as _rdrand_step, _rdseed64_step as _rdseed_step};

#[cfg(target_arch = "aarch64")]
mod aarch64_rdrand {
    #[inline]
    pub fn _rdrand_step(val: &mut u64) -> i32 {
        if std::arch::is_aarch64_feature_detected!("rand") {
            (unsafe { rdrand_impl::__rndr(val) } == 0) as i32
        } else {
            *val = 0;
            0
        }
    }

    #[inline]
    pub fn _rdseed_step(val: &mut u64) -> i32 {
        if std::arch::is_aarch64_feature_detected!("rand") {
            (unsafe { rdrand_impl::__rndrrs(val) } == 0) as i32
        } else {
            *val = 0;
            0
        }
    }

    #[cfg(all(nightly, not(feature = "rdrand_stable")))]
    mod rdrand_impl {
        pub use core::arch::aarch64::{__rndr, __rndrrs};
    }

    #[cfg(any(not(nightly), feature = "rdrand_stable"))]
    mod rdrand_impl {
        #[inline]
        pub unsafe fn __rndr(val: *mut u64) -> i32 {
            let value: u64;
            let success: u32;

            core::arch::asm!(
                "mrs {value}, S3_3_C2_C4_0",
                "cset {success:w}, eq",
                value = out(reg) value,
                success = out(reg) success,
                options(nostack),
            );

            unsafe { *val = value };

            success as i32
        }

        #[inline]
        pub unsafe fn __rndrrs(val: *mut u64) -> i32 {
            let value: u64;
            let success: u32;

            core::arch::asm!(
                "mrs {value}, S3_3_C2_C4_1",
                "cset {success:w}, eq",
                value = out(reg) value,
                success = out(reg) success,
                options(nostack),
            );

            unsafe { *val = value };

            success as i32
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn rndr_test() {
            let mut value = 0u64;
            assert_eq!(_rdrand_step(&mut value), 1);
            assert!(value != 0);
        }

        #[test]
        fn rndrrs_test() {
            let mut value = 0u64;
            assert_eq!(_rdseed_step(&mut value), 1);
            assert!(value != 0);
        }
    }
}

// Intel documentation claims that if hardware is working RDRAND will produce
// output after at most 10 attempts
// https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
// section 5.2.1
const RDRAND_READ_ATTEMPTS: usize = 10;

// Intel does not document the number of times RDSEED might consecutively fail,
// but in example code uses 75 as the upper bound.
const RDSEED_READ_ATTEMPTS: usize = 75;

fn call_cpu_rng<T, F>(attempts: usize, intrin: unsafe fn(&mut T) -> i32, cast: F) -> Option<usize>
where
    T: Sized + Default,
    F: FnOnce(T) -> usize,
{
    assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<usize>());

    for _ in 0..attempts {
        let mut out = T::default();
        let status = unsafe { intrin(&mut out) };
        if status == 1 {
            return Some(cast(out));
        }
    }
    None
}

fn rdrand() -> Option<usize> {
    call_cpu_rng(RDRAND_READ_ATTEMPTS, _rdrand_step, |x| x as usize)
}

fn rdseed() -> Option<usize> {
    call_cpu_rng(RDSEED_READ_ATTEMPTS, _rdseed_step, |x| x as usize)
}

fn write_rng_to_slice(outbuf: &mut [u8], rng: fn() -> Option<usize>) -> c_int {
    let stepsize = core::mem::size_of::<usize>();

    for chunk in outbuf.chunks_mut(stepsize) {
        if let Some(val) = rng() {
            let buf = val.to_ne_bytes();
            let ptr = &buf[..chunk.len()];
            chunk.copy_from_slice(ptr);
        } else {
            return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
        }
    }
    0
}

use super::{EntropyCallback, EntropyCallbackMut, RngCallback, RngCallbackMut};

pub struct Entropy;

impl EntropyCallback for Entropy {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let mut outbuf = from_raw_parts_mut(data, len);
        write_rng_to_slice(&mut outbuf, rdseed)
    }

    fn data_ptr(&self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

impl EntropyCallbackMut for Entropy {
    unsafe extern "C" fn call_mut(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let mut outbuf = from_raw_parts_mut(data, len);
        write_rng_to_slice(&mut outbuf, rdseed)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

pub struct Nrbg;

impl RngCallbackMut for Nrbg {
    unsafe extern "C" fn call_mut(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // outbuf data/len are stack variables
        let mut outbuf = from_raw_parts_mut(data, len);

        // rdrand function is thread safe
        write_rng_to_slice(&mut outbuf, rdrand)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

impl RngCallback for Nrbg {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // outbuf data/len are stack variables
        let mut outbuf = from_raw_parts_mut(data, len);

        // rdrand function is thread safe
        write_rng_to_slice(&mut outbuf, rdrand)
    }

    fn data_ptr(&self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
