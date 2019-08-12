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
const RDRAND_READ_ATTEMPTS : i32 = 10;

// Intel does not document the number of times RDSEED might consecutively fail, but in
// example code uses 75 as the upper bound.
const RDSEED_READ_ATTEMPTS : i32 = 75;

fn call_cpu_rng<T: Sized + Copy>(attempts: i32, intrin: unsafe fn(&mut T) -> i32) -> Option<T> {
    let mut attempts = attempts;
    while attempts > 0 {
        let mut out : T = unsafe { std::mem::uninitialized() };
        let status = unsafe { intrin(&mut out) };
        if status == 1 {
            return Some(out);
        }
        attempts -= 1;
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn rdrand() -> Option<u64> {
    call_cpu_rng(RDRAND_READ_ATTEMPTS, core::arch::x86_64::_rdrand64_step)
}

#[cfg(target_arch = "x86_64")]
fn rdseed() -> Option<u64> {
    call_cpu_rng(RDSEED_READ_ATTEMPTS, core::arch::x86_64::_rdseed64_step)
}

#[cfg(target_arch = "x86")]
fn rdrand() -> Option<u32> {
    call_cpu_rng(RDRAND_READ_ATTEMPTS, core::arch::x86::_rdrand32_step)
}

#[cfg(target_arch = "x86")]
fn rdseed() -> Option<u32> {
    call_cpu_rng(RDSEED_READ_ATTEMPTS, core::arch::x86::_rdseed32_step)
}

use super::{EntropyCallback, RngCallback};

pub struct Entropy;

impl EntropyCallback for Entropy {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = from_raw_parts_mut(data, len);

        let stepsize = if cfg!(target_arch = "x86_64") { 8 } else { 4 };

        for chunk in outbuf.chunks_mut(stepsize) {
            if let Some(val) = rdseed() {
                let mut buf = [0u8; 8];
                ::core::ptr::copy_nonoverlapping(&val as *const _ as *const u8, buf.as_mut_ptr(), stepsize);
                let ptr = &buf[..chunk.len()];
                chunk.copy_from_slice(ptr);
            }
            else {
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

        let stepsize = if cfg!(target_arch = "x86_64") { 8 } else { 4 };

        for chunk in outbuf.chunks_mut(stepsize) {
            if let Some(val) = rdrand() {
                let mut buf = [0u8; 8];
                ::core::ptr::copy_nonoverlapping(&val as *const _ as *const u8, buf.as_mut_ptr(), stepsize);
                let ptr = &buf[..chunk.len()];
                chunk.copy_from_slice(ptr);
            }
            else {
                return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
            }
        }
        0
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
