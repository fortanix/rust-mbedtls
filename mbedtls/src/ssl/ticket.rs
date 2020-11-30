/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(feature = "std")]
use std::sync::Arc;

use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::cipher::raw::CipherType;
use crate::error::{IntoResult, Result};
use crate::rng::RngCallback;


#[cfg(not(feature = "threading"))]
pub trait TicketCallback {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int where Self: Sized;
    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int where Self: Sized;

    fn data_ptr(&self) -> *mut c_void;
}

#[cfg(feature = "threading")]
pub trait TicketCallback : Sync {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int where Self: Sized;
    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int where Self: Sized;

    fn data_ptr(&self) -> *mut c_void;
}


define!(
    #[c_ty(ssl_ticket_context)]
    #[repr(C)]
    struct TicketContext {
        // We set rng from constructur, we never read it directly. It is only used to ensure rng lives as long as we need.
        #[allow(dead_code)]
        rng: Arc<dyn RngCallback + Send + 'static>,
    };
    const drop: fn(&mut Self) = ssl_ticket_free;
    impl<'a> Into<ptr> {}
);

#[cfg(feature = "threading")]
unsafe impl Sync for TicketContext {}

impl TicketContext {
    pub fn new<T: RngCallback + Send + 'static>(
        rng: Arc<T>,
        cipher: CipherType,
        lifetime: u32,
    ) -> Result<TicketContext> {

        let mut ret = TicketContext { inner: ssl_ticket_context::default(), rng };

        unsafe {
            ssl_ticket_init(&mut ret.inner);
            ssl_ticket_setup(
                &mut ret.inner,
                Some(T::call),
                ret.rng.data_ptr(),
                cipher.into(),
                lifetime,
            ).into_result()?;
        }

        Ok(ret)
    }
}

impl TicketCallback for TicketContext {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int {
        ssl_ticket_write(p_ticket, session, start, end, tlen, lifetime)
    }

    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int {
        ssl_ticket_parse(p_ticket, session, buf, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        self.handle() as *const _ as *mut _
    }
}
