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

use super::{EntropyCallback, RngCallback};

pub struct Entropy;

impl EntropyCallback for Entropy {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = from_raw_parts_mut(data, len);
        for chunk in outbuf.chunks_mut(8) {
            let ret;
            let mut retry = 10;
            asm!("
1:
                rdseed $0
                jc 2f
                dec $1
                jnz 1b
2:
            ":"=r"(ret),"=r"(retry):"1"(retry)::"volatile");
            if retry == 0 {
                return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
            }
            let rand = ::core::mem::transmute::<u64, [u8; 8]>(ret);
            let ptr = &rand[..chunk.len()];
            chunk.copy_from_slice(ptr);
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
        for chunk in outbuf.chunks_mut(8) {
            let ret;
            let mut retry = 10;
            asm!("
1:
                rdrand $0
                jc 2f
                dec $1
                jnz 1b
2:
            ":"=r"(ret),"=r"(retry):"1"(retry)::"volatile");
            if retry == 0 {
                return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
            }
            let rand = ::core::mem::transmute::<u64, [u8; 8]>(ret);
            let ptr = &rand[..chunk.len()];
            chunk.copy_from_slice(ptr);
        }
        0
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
