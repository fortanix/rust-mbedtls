/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::result::Result as StdResult;

#[cfg(feature = "std")]
use {
    std::io::{Read, Write, Result as IoResult},
    std::sync::Arc,
};

#[cfg(not(feature = "std"))]
use core_io::{Read, Write, Result as IoResult, ErrorKind as IoErrorKind};

#[cfg(all(feature = "std", feature = "async"))]
use {
    std::io::{Error as IoError, ErrorKind as IoErrorKind},
    std::marker::Unpin,
    std::pin::Pin,
    std::task::{Context as TaskContext, Poll},
};
    

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

#[cfg(all(feature = "std", feature = "async"))]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::alloc::{List as MbedtlsList};
use crate::error::{Error, Result, IntoResult};
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::ssl::config::{Config, Version, AuthMode};
#[cfg(all(feature = "std", feature = "async"))]
use crate::ssl::async_utils::IoAdapter;
use crate::x509::{Certificate, Crl, VerifyError};

pub trait IoCallback {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int where Self: Sized;
    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int where Self: Sized;
    fn data_ptr(&mut self) -> *mut c_void;
}

impl<IO: Read + Write + 'static> IoCallback for IO {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).read(::core::slice::from_raw_parts_mut(data, len)) {
            Ok(i) => i as c_int,
            Err(_) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
        }
    }

    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).write(::core::slice::from_raw_parts(data, len)) {
            Ok(i) => i as c_int,
            Err(_) => ::mbedtls_sys::ERR_NET_SEND_FAILED,
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut IO as *mut _
    }
}


define!(
    #[c_ty(ssl_context)]
    #[repr(C)]
    struct HandshakeContext {
        handshake_ca_cert: Option<Arc<MbedtlsList<Certificate>>>,
        handshake_crl: Option<Arc<Crl>>,
        
        handshake_cert: Vec<Arc<MbedtlsList<Certificate>>>,
        handshake_pk: Vec<Arc<Pk>>,
    };
    impl<'a> Into<ptr> {}

    // Only use this when you know the type you are casting is originally a rust allocated 'Context'.
    impl<'a> UnsafeFrom<ptr> {}
);

define!(
    #[c_custom_ty(ssl_context)]
    #[repr(C)]
    struct Context<T> {
        // Base structure used in SNI callback where we cannot determine the io type.
        inner: HandshakeContext,
        
        // config is used read-only for mutliple contexts and is immutable once configured.
        config: Arc<Config>, 

        // Must be held in heap and pointer to it as pointer is sent to MbedSSL and can't be re-allocated.
        io: Option<Box<T>>,
    };
    impl<'a> Into<ptr> {}
);

#[cfg(all(feature = "std", feature = "async"))]
pub type AsyncContext<T> = Context<IoAdapter<T>>;


impl<T> Context<T> {
    pub fn new(config: Arc<Config>) -> Self {
        let mut inner = ssl_context::default();
        
        unsafe {
            ssl_init(&mut inner);
            ssl_setup(&mut inner, (&*config).into());
        };

        Context {
            inner: HandshakeContext {
                inner,
                handshake_ca_cert: None,
                handshake_crl: None,
                
                handshake_cert: vec![],
                handshake_pk: vec![],
            },
            config: config.clone(),
            io: None,
        }
    }
}

impl<T: IoCallback + Send + Sync + 'static> Context<T> {
    pub fn establish(&mut self, io: T, hostname: Option<&str>) -> Result<()> {
        unsafe {
            let mut io = Box::new(io);
            ssl_session_reset(self.into()).into_result()?;
            self.set_hostname(hostname)?;

            let ptr = &mut *io as *mut _ as *mut c_void;
            ssl_set_bio(
                self.into(),
                ptr,
                Some(T::call_send),
                Some(T::call_recv),
                None,
            );

            self.io = Some(io);
            self.inner.reset_handshake();            
        }

        self.handshake()
    }
}

impl<T> Context<T> {
    pub fn handshake(&mut self) -> Result<()> {
        match unsafe { ssl_flush_output(self.into()).into_result() } {
            Err(Error::SslWantRead) => Err(Error::SslWantRead),
            Err(Error::SslWantWrite) => Err(Error::SslWantWrite),
            Err(e) => {
                unsafe { ssl_set_bio(self.into(), ::core::ptr::null_mut(), None, None, None); }
                self.io = None;
                Err(e)
            },
            Ok(_) => {
                match unsafe { ssl_handshake(self.into()).into_result() } {
                    Err(Error::SslWantRead) => Err(Error::SslWantRead),
                    Err(Error::SslWantWrite) => Err(Error::SslWantWrite),
                    Err(e) => {
                        unsafe { ssl_set_bio(self.into(), ::core::ptr::null_mut(), None, None, None); }
                        self.io = None;
                        Err(e)
                    },
                    Ok(_) => {
                        Ok(())
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "std"))]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        match hostname {
            Some(_) => Err(Error::SslBadInputData),
            None => Ok(()),
        }
    }

    #[cfg(feature = "std")]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        if let Some(s) = hostname {
            let cstr = ::std::ffi::CString::new(s).map_err(|_| Error::SslBadInputData)?;
            unsafe {
                ssl_set_hostname(self.into(), cstr.as_ptr())
                    .into_result()
                    .map(|_| ())
            }
        } else {
            Ok(())
        }
    }

    pub fn verify_result(&self) -> StdResult<(), VerifyError> {
        match unsafe { ssl_get_verify_result(self.into()) } {
            0 => Ok(()),
            flags => Err(VerifyError::from_bits_truncate(flags)),
        }
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }
    
    pub fn close(&mut self) {
        unsafe {
            ssl_close_notify(self.into());
            ssl_set_bio(self.into(), ::core::ptr::null_mut(), None, None, None);
            self.io = None;
        }
    }
    pub fn io(&self) -> Option<&T> {
        self.io.as_ref().map(|v| &**v)
    }
    pub fn io_mut(&mut self) -> Option<&mut T> {
        self.io.as_mut().map(|v| &mut **v)
    }
    
    /// Return the minor number of the negotiated TLS version
    pub fn minor_version(&self) -> i32 {
        self.handle().minor_ver
    }

    /// Return the major number of the negotiated TLS version
    pub fn major_version(&self) -> i32 {
        self.handle().major_ver
    }

    /// Return the number of bytes currently available to read that
    /// are stored in the Session's internal read buffer
    pub fn bytes_available(&self) -> usize {
        unsafe { ssl_get_bytes_avail(self.into()) }
    }

    pub fn version(&self) -> Version {
        let major = self.major_version();
        assert_eq!(major, 3);
        let minor = self.minor_version();
        match minor {
            0 => Version::Ssl3,
            1 => Version::Tls1_0,
            2 => Version::Tls1_1,
            3 => Version::Tls1_2,
            _ => unreachable!("unexpected TLS version")
        }
    }


    // Session specific functions
    
    /// Return the 16-bit ciphersuite identifier.
    /// All assigned ciphersuites are listed by the IANA in
    /// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
    pub fn ciphersuite(&self) -> Result<u16> {
        if self.handle().session.is_null() {
            return Err(Error::SslBadInputData);
        }
        
        Ok(unsafe { self.handle().session.as_ref().unwrap().ciphersuite as u16 })
    }

    pub fn peer_cert(&self) -> Result<Option<&MbedtlsList<Certificate>>> {
        if self.handle().session.is_null() {
            return Err(Error::SslBadInputData);
        }

        unsafe {
            // We cannot call the peer cert function as we need a pointer to a pointer to create the MbedtlsList, we need something in the heap / cannot use any local variable for that.
            let peer_cert : &MbedtlsList<Certificate> = UnsafeFrom::from(&((*self.handle().session).peer_cert) as *const *mut x509_crt as *const *const x509_crt).ok_or(Error::SslBadInputData)?;
            Ok(Some(peer_cert))
        }
    }


    #[cfg(feature = "std")]
    pub fn get_alpn_protocol(&self) -> Result<Option<&str>> {
        unsafe {
            let ptr = ssl_get_alpn_protocol(self.handle());
            if ptr.is_null() {
                Ok(None)
            } else {
                let s = std::ffi::CStr::from_ptr(ptr).to_str()?;
                Ok(Some(s))
            }
        }
    }
}

impl<T> Drop for Context<T> {
    fn drop(&mut self) {
        unsafe {
            self.close();
            ssl_free(self.into());
        }
    }
}

impl<T: Read> Read for Context<T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match unsafe { ssl_read(self.into(), buf.as_mut_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }
}

impl<T: Write> Write for Context<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match unsafe { ssl_write(self.into(), buf.as_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}
//
// Class exists only during SNI callback that is configured from Config.
// SNI Callback must provide input whos lifetime exceed the SNI closure to avoid memory corruptions.
// That can be achieved easily by storing certificate chains/crls inside the closure for the lifetime of the closure.
//
// That is due to SNI being held by an Arc inside Config.
// Config lives longer then Context. Context lives longer then Handshake.
//
// Alternatives are not possible due to:
// - mbedtls not providing any callbacks on handshake finish.
// - no reasonable way to obtain a storage within the sni callback tied to the handshake or to the rust Context. (without resorting to a unscalable map or pointer magic that mbedtls may invalidate)
//
impl HandshakeContext {
    pub fn reset_handshake(&mut self) {
        self.handshake_cert.clear();
        self.handshake_pk.clear();
        self.handshake_ca_cert = None;
        self.handshake_crl = None;
    }
    
    pub fn set_authmode(&mut self, am: AuthMode) -> Result<()> {
        if self.inner.handshake as *const _ == ::core::ptr::null() {
            return Err(Error::SslBadInputData);
        }
        
        unsafe { ssl_set_hs_authmode(self.into(), am as i32) }
        Ok(())
    }

    pub fn set_ca_list(
        &mut self,
        chain: Option<Arc<MbedtlsList<Certificate>>>,
        crl: Option<Arc<Crl>>,
    ) -> Result<()> {
        // mbedtls_ssl_set_hs_ca_chain does not check for NULL handshake.
        if self.inner.handshake as *const _ == ::core::ptr::null() {
            return Err(Error::SslBadInputData);
        }

        // This will override current handshake CA chain.
        unsafe {
            ssl_set_hs_ca_chain(
                self.into(),
                chain.as_ref().map(|chain| chain.inner_ffi_mut()).unwrap_or(::core::ptr::null_mut()),
                crl.as_ref().map(|crl| crl.inner_ffi_mut()).unwrap_or(::core::ptr::null_mut()),
            );
        }

        self.handshake_ca_cert = chain;
        self.handshake_crl = crl;
        Ok(())
    }

    /// If this is never called, will use the set of private keys and
    /// certificates configured in the `Config` associated with this `Context`.
    /// If this is called at least once, all those are ignored and the set
    /// specified using this function is used.
    pub fn push_cert(
        &mut self,
        chain: Arc<MbedtlsList<Certificate>>,
        key: Arc<Pk>,
    ) -> Result<()> {
        // mbedtls_ssl_set_hs_own_cert does not check for NULL handshake.
        if self.inner.handshake as *const _ == ::core::ptr::null() {
            return Err(Error::SslBadInputData);
        }

        // This will append provided certificate pointers in internal structures.
        unsafe {
            ssl_set_hs_own_cert(self.into(), chain.inner_ffi_mut(), key.inner_ffi_mut()).into_result()?;
        }
        self.handshake_cert.push(chain);
        self.handshake_pk.push(key);

        Ok(())
    }
}

#[cfg(all(feature = "std", feature = "async"))]
pub trait IoAsyncCallback {
    unsafe extern "C" fn call_recv_async(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int where Self: Sized;
    unsafe extern "C" fn call_send_async(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int where Self: Sized;
}

#[cfg(all(feature = "std", feature = "async"))]
impl<IO: AsyncRead + AsyncWrite + Unpin + 'static> IoAsyncCallback for IoAdapter<IO> {
    unsafe extern "C" fn call_recv_async(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };

        let adapter = &mut *(user_data as *mut IoAdapter<IO>);

        if let Some(cx) = adapter.ecx.get() {
            let mut buf = ReadBuf::new(::core::slice::from_raw_parts_mut(data, len));
            let stream = Pin::new(&mut adapter.inner);

            match stream.poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => buf.filled().len() as c_int,
                Poll::Ready(Err(_)) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
                Poll::Pending => ::mbedtls_sys::ERR_SSL_WANT_READ,
            }
        } else {
            ::mbedtls_sys::ERR_NET_RECV_FAILED
        }
    }

    unsafe extern "C" fn call_send_async(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };

        let adapter = &mut *(user_data as *mut IoAdapter<IO>);

        if let Some(cx) = adapter.ecx.get() {
            let stream = Pin::new(&mut adapter.inner);

            match stream.poll_write(cx, ::core::slice::from_raw_parts(data, len)) {
                Poll::Ready(Ok(i)) => i as c_int,
                Poll::Ready(Err(_)) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
                Poll::Pending => ::mbedtls_sys::ERR_SSL_WANT_WRITE,
            }
        } else {
            ::mbedtls_sys::ERR_NET_RECV_FAILED
        }
    }
}

#[cfg(all(feature = "std", feature = "async"))]
struct HandshakeFuture<'a, T>(&'a mut Context::<IoAdapter<T>>);

#[cfg(all(feature = "std", feature = "async"))]
impl<T> std::future::Future for HandshakeFuture<'_, T> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut TaskContext) -> std::task::Poll<Self::Output> {
        self.0.io_mut().ok_or(Error::NetInvalidContext)?
                       .ecx.set(ctx);
        
        let result = match self.0.handshake() {
            Err(Error::SslWantRead) |
            Err(Error::SslWantWrite) => {
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) => Poll::Ready(Ok(()))
        };
        
        self.0.io_mut().map(|v| v.ecx.clear());
        
        result
    }
}

#[cfg(all(feature = "std", feature = "async"))]
impl<T: AsyncRead + AsyncWrite + Unpin + 'static> AsyncContext<T> {
    pub async fn accept_async(config: Arc<Config>, io: T, hostname: Option<&str>) -> IoResult<AsyncContext<T>> {
        let mut context = Self::new(config);
        context.establish_async(io, hostname).await.map_err(|e| crate::private::error_to_io_error(e))?;
        Ok(context)
    }

    pub async fn establish_async(&mut self, io: T, hostname: Option<&str>) -> Result<()> {
        unsafe {
            let mut io = Box::new(IoAdapter::new(io));

            ssl_session_reset(self.into()).into_result()?;
            self.set_hostname(hostname)?;

            let ptr = &mut *io as *mut _ as *mut c_void;
            ssl_set_bio(
                self.into(),
                ptr,
                Some(IoAdapter::<T>::call_send_async),
                Some(IoAdapter::<T>::call_recv_async),
                None,
            );

            self.io = Some(io);
            self.inner.reset_handshake();            
        }

        HandshakeFuture(self).await
    }
}

#[cfg(all(feature = "std", feature = "async"))]
impl<T: AsyncRead> AsyncRead for Context<IoAdapter<T>> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {

        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
                     .ecx.set(cx);
        
        let result = match unsafe { ssl_read((&mut *self).into(), buf.initialize_unfilled().as_mut_ptr(), buf.initialize_unfilled().len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(())),
            Err(Error::SslWantRead) => Poll::Pending,
            Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
            Ok(i) => {
                buf.advance(i as usize);
                Poll::Ready(Ok(()))
            }
        };

        self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
                     .ecx.clear();

        result
    }
}

#[cfg(all(feature = "std", feature = "async"))]
impl<T: AsyncWrite + Unpin> AsyncWrite for Context<IoAdapter<T>> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {

        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        let buf = {
            let io = self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?;
            io.ecx.set(cx);
            io.write_tracker.adjust_buf(buf)
        }?;

        
        self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
                     .ecx.set(cx);
        
        let result = match unsafe { ssl_write((&mut *self).into(), buf.as_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
            Err(Error::SslWantWrite) => Poll::Pending,
            Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
            Ok(i) => Poll::Ready(Ok(i as usize))
        };

        let io = self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?;

        io.ecx.clear();
        io.write_tracker.post_write(buf, &result);

        cx.waker().clone().wake();

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        // We can only flush the actual IO here.
        // To flush mbedtls we need writes with the same buffer until complete.
        let io = &mut self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
                                   .inner;
        let stream = Pin::new(io);
        stream.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        self.io_mut().ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
                     .ecx.set(cx);

        let result = match unsafe { ssl_close_notify((&mut *self).into()).into_result() } {
            Err(Error::SslWantRead) |
            Err(Error::SslWantWrite) => Poll::Pending,
            Err(e) => {
                unsafe { ssl_set_bio((&mut *self).into(), ::core::ptr::null_mut(), None, None, None); }
                self.io = None;
                Poll::Ready(Err(crate::private::error_to_io_error(e)))
            }
            Ok(0) => {
                unsafe { ssl_set_bio((&mut *self).into(), ::core::ptr::null_mut(), None, None, None); }
                self.io = None;
                Poll::Ready(Ok(()))
            }
            Ok(v) => {
                unsafe { ssl_set_bio((&mut *self).into(), ::core::ptr::null_mut(), None, None, None); }
                self.io = None;
                Poll::Ready(Err(IoError::new(IoErrorKind::Other, format!("unexpected result from ssl_close_notify: {}", v))))
            }
        };

        self.io_mut().map(|v| v.ecx.clear());
        result
    }
}


// ssl_get_alpn_protocol
// ssl_get_max_frag_len
// ssl_get_record_expansion
// ssl_get_verify_result
// ssl_get_version
// ssl_renegotiate
// ssl_send_alert_message
// ssl_set_client_transport_id
// ssl_set_hs_psk
// ssl_set_timer_cb
//
// ssl_handshake_step
//
// CLIENT SIDE SESSIONS
// ssl_session_free
// ssl_session_init
// ssl_get_session
// ssl_set_session
//
// SERVER SIDE SESSIONS (ssl_conf_session_cache)
// ssl_cache_free
// ssl_cache_get
// ssl_cache_init
// ssl_cache_set
// ssl_cache_set_max_entries
//
// CIPHER SUITES
// ssl_ciphersuite_from_id
// ssl_ciphersuite_from_string
// ssl_ciphersuite_uses_ec
// ssl_ciphersuite_uses_psk
// ssl_get_ciphersuite_id
// ssl_get_ciphersuite_name
// ssl_get_ciphersuite_sig_pk_alg
// ssl_list_ciphersuites
//
// DTLS SERVER COOKIES (ssl_conf_dtls_cookies)
// ssl_cookie_check
// ssl_cookie_free
// ssl_cookie_init
// ssl_cookie_set_timeout
// ssl_cookie_setup
// ssl_cookie_write
//
// INTERNAL
// ssl_check_cert_usage
// ssl_check_curve
// ssl_check_sig_hash
// ssl_derive_keys
// ssl_dtls_replay_check
// ssl_dtls_replay_update
// ssl_fetch_input
// ssl_flush_output
// ssl_handshake_client_step
// ssl_handshake_free
// ssl_handshake_server_step
// ssl_handshake_wrapup
// ssl_hash_from_md_alg
// ssl_md_alg_from_hash
// ssl_optimize_checksum
// ssl_parse_certificate
// ssl_parse_change_cipher_spec
// ssl_parse_finished
// ssl_pk_alg_from_sig
// ssl_psk_derive_premaster
// ssl_read_record
// ssl_read_version
// ssl_recv_flight_completed
// ssl_resend
// ssl_reset_checksum
// ssl_send_fatal_handshake_failure
// ssl_send_flight_completed
// ssl_sig_from_pk
// ssl_transform_free
// ssl_write_certificate
// ssl_write_change_cipher_spec
// ssl_write_finished
// ssl_write_record
// ssl_write_version
//
