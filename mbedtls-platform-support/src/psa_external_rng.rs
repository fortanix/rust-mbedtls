/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_void, c_uchar};
use mbedtls_sys::types::{size_t, int32_t};
use once_cell::sync::OnceCell;
static PSA_CALLBACK_INIT: OnceCell<()> = OnceCell::new();

struct PsaExternlRng {}

impl PsaExternlRng {
    unsafe extern "C" fn dummy_callback(
        _user_data: *mut c_void,
        _data: *mut c_uchar,
        _len: size_t,
        _olen: *mut size_t,
    ) -> int32_t {
        panic!("The global function pointer `mbedtls_psa_external_get_random` is uninitialized");
    }
}

type PsaExternlRngCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    data: *mut c_uchar,
    len: size_t,
    olen: *mut size_t,
) -> int32_t;

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut mbedtls_psa_external_get_random: PsaExternlRngCallback = PsaExternlRng::dummy_callback;

pub fn set_psa_external_rng_callback(
    callback: PsaExternlRngCallback
) {
    PSA_CALLBACK_INIT.get_or_init(|| {
        unsafe { mbedtls_psa_external_get_random = callback; }
        return ();
    });
}