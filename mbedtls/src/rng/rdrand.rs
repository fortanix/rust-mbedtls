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

// Intel documentation claims that if hardware is working RDRAND will produce output
// after at most 10 attempts
const RDRAND_READ_ATTEMPTS: usize = 10;

// Intel does not document the number of times RDSEED might consecutively fail, but in
// example code uses 75 as the upper bound.
const RDSEED_READ_ATTEMPTS: usize = 75;

fn call_cpu_rng<T, F>(attempts: usize, intrin: unsafe fn(&mut T) -> i32, cast_to_usize: F) -> Option<usize>
where
    T: Sized + Copy + Default,
    F: FnOnce(T) -> usize,
{
    for _ in 0..attempts {
        let mut out = T::default();
        let status = unsafe { intrin(&mut out) };
        if status == 1 {
            return Some(cast_to_usize(out));
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn rdrand() -> Option<usize> {
    call_cpu_rng(
        RDRAND_READ_ATTEMPTS,
        core::arch::x86_64::_rdrand64_step,
        |x:u64| -> usize { x as usize }
    )
}

#[cfg(target_arch = "x86_64")]
fn rdseed() -> Option<usize> {
    call_cpu_rng(
        RDSEED_READ_ATTEMPTS,
        core::arch::x86_64::_rdseed64_step,
        |x:u64| -> usize { x as usize }
    )
}

#[cfg(target_arch = "x86")]
fn rdrand() -> Option<usize> {
    call_cpu_rng(
        RDRAND_READ_ATTEMPTS,
        core::arch::x86::_rdrand32_step,
        |x:u32| -> usize { x as usize }
    )
}

#[cfg(target_arch = "x86")]
fn rdseed() -> Option<usize> {
    call_cpu_rng(
        RDSEED_READ_ATTEMPTS,
        core::arch::x86::_rdseed32_step,
        |x:u32| -> usize { x as usize }
    )
}

use super::{EntropyCallback, RngCallback};

pub struct Entropy;

impl EntropyCallback for Entropy {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = from_raw_parts_mut(data, len);

        let stepsize = core::mem::size_of::<usize>();

        for chunk in outbuf.chunks_mut(stepsize) {
            if let Some(val) = rdseed() {
                let buf = val.to_ne_bytes();
                let ptr = &buf[..chunk.len()];
                chunk.copy_from_slice(ptr);
            } else {
                return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
            }
        }
        0
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

pub struct Nrbg;

impl RngCallback for Nrbg {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = from_raw_parts_mut(data, len);

        let stepsize = core::mem::size_of::<usize>();

        for chunk in outbuf.chunks_mut(stepsize) {
            if let Some(val) = rdrand() {
                let buf = val.to_ne_bytes();
                let ptr = &buf[..chunk.len()];
                chunk.copy_from_slice(ptr);
            } else {
                return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
            }
        }
        0
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
