#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
#[cfg(feature = "std")]
use std::sync::Arc;

use mbedtls_sys::types::raw_types::*;
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use crate::error::{IntoResult, Result};
use crate::rng::RngCallback;

pub trait CookieCallback {
    /*
    typedef int mbedtls_ssl_cookie_write_t( void *ctx,
                                    unsigned char **p, unsigned char *end,
                                    const unsigned char *info, size_t ilen );
    */
    unsafe extern "C" fn cookie_write(
        ctx: *mut c_void,
        p: *mut *mut c_uchar,
        end: *mut c_uchar,
        info: *const c_uchar,
        ilen: size_t,
    ) -> c_int
    where
        Self: Sized;
    /*
    typedef int mbedtls_ssl_cookie_check_t( void *ctx,
                                    const unsigned char *cookie, size_t clen,
                                    const unsigned char *info, size_t ilen );
    */
    unsafe extern "C" fn cookie_check(
        ctx: *mut c_void,
        cookie: *const c_uchar,
        clen: size_t,
        info: *const c_uchar,
        ilen: size_t,
    ) -> c_int
    where
        Self: Sized;

    /// Returns a mutable pointer to this shared reference which will be used as first argument to
    /// the other two methods
    ///
    /// A mutable pointer is required because the underlying cookie implementation should be
    /// allowed to store some information, e.g. mbedtls' implementation uses an internal counter.
    /// We only have a shared reference because in general, the `CookieCallback` will be behind an
    /// `Arc<dyn CookieCallback>` (in [`Config`]). So we need to remove const-ness here which is
    /// unsafe in general. Each respective implementation has to guarantee that shared accesses are
    /// safe. mbedtls' implementation uses internal mutexes in multithreaded contexts (when the
    /// `threading` feature is activated) to do so.
    fn data_ptr(&self) -> *mut c_void;
}

define!(
    #[c_ty(ssl_cookie_ctx)]
    #[repr(C)]
    struct CookieContext {
        // We set rng from constructor, we never read it directly. It is only used to ensure rng lives as long as we need.
        #[allow(dead_code)]
        rng: Arc<dyn RngCallback + Send + 'static>,
    };
    const drop: fn(&mut Self) = ssl_cookie_free;
    impl<'a> Into<ptr> {}
);

unsafe impl Sync for CookieContext {}

impl CookieContext {
    pub fn new<T: RngCallback + Send + 'static>(rng: Arc<T>) -> Result<CookieContext> {
        let mut ret = CookieContext {
            inner: ssl_cookie_ctx::default(),
            rng,
        };

        unsafe {
            ssl_cookie_init(&mut ret.inner);
            ssl_cookie_setup(&mut ret.inner, Some(T::call), ret.rng.data_ptr()).into_result()?;
        }

        Ok(ret)
    }
}

impl CookieCallback for CookieContext {
    unsafe extern "C" fn cookie_write(
        ctx: *mut c_void,
        p: *mut *mut c_uchar,
        end: *mut c_uchar,
        info: *const c_uchar,
        ilen: size_t,
    ) -> c_int
    where
        Self: Sized,
    {
        ssl_cookie_write(ctx, p, end, info, ilen)
    }

    unsafe extern "C" fn cookie_check(
        ctx: *mut c_void,
        cookie: *const c_uchar,
        clen: size_t,
        info: *const c_uchar,
        ilen: size_t,
    ) -> c_int
    where
        Self: Sized,
    {
        ssl_cookie_check(ctx, cookie, clen, info, ilen)
    }

    fn data_ptr(&self) -> *mut c_void {
        self.handle() as *const _ as *mut _
    }
}
