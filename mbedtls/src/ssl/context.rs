/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::result::Result as StdResult;

#[cfg(feature = "std")]
use std::sync::Arc;

use mbedtls_sys::types::raw_types::{c_int, c_void};
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::alloc::List as MbedtlsList;
use crate::error::{Error, Result, IntoResult, codes};
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::ssl::config::{Config, Version, AuthMode};
use crate::ssl::io::IoCallbackUnsafe;
use crate::x509::{Certificate, Crl, VerifyError};

pub trait TimerCallback: Send + Sync {
    unsafe extern "C" fn set_timer(
        p_timer: *mut c_void,
        int_ms: u32,
        fin_ms: u32,
    ) where Self: Sized;

    unsafe extern "C" fn get_timer(
        p_timer: *mut c_void,
    ) -> c_int where Self: Sized;

    fn data_ptr(&mut self) -> *mut c_void;
}

#[cfg(feature = "std")]
pub struct Timer {
    timer_start: std::time::Instant,
    timer_int_ms: u32,
    timer_fin_ms: u32,
}

#[cfg(feature = "std")]
impl Timer {
    pub fn new() -> Self {
        Timer {
            timer_start: std::time::Instant::now(),
            timer_int_ms: 0,
            timer_fin_ms: 0,
        }
    }
}

#[cfg(feature = "std")]
impl TimerCallback for Timer {
    unsafe extern "C" fn set_timer(
        p_timer: *mut c_void,
        int_ms: u32,
        fin_ms: u32,
    ) where Self: Sized {
        let slf = (p_timer as *mut Timer).as_mut().unwrap();
        slf.timer_start = std::time::Instant::now();
        slf.timer_int_ms = int_ms;
        slf.timer_fin_ms = fin_ms;
    }

    unsafe extern "C" fn get_timer(
        p_timer: *mut c_void,
    ) -> c_int where Self: Sized {
        let slf = (p_timer as *mut Timer).as_mut().unwrap();
        if slf.timer_int_ms == 0 || slf.timer_fin_ms == 0 {
            return 0;
        }
        let passed = std::time::Instant::now() - slf.timer_start;
        if passed.as_millis() >= slf.timer_fin_ms.into() {
            2
        } else if passed.as_millis() >= slf.timer_int_ms.into() {
            1
        } else {
            0
        }
    }

    fn data_ptr(&mut self) -> *mut mbedtls_sys::types::raw_types::c_void {
        self as *mut _ as *mut _
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

#[repr(C)]
pub struct Context<T> {
    // Base structure used in SNI callback where we cannot determine the io type.
    inner: HandshakeContext,
    
    // config is used read-only for multiple contexts and is immutable once configured.
    config: Arc<Config>, 
    
    // Must be held in heap and pointer to it as pointer is sent to MbedSSL and can't be re-allocated.
    io: Option<Box<T>>,

    timer_callback: Option<Box<dyn TimerCallback>>,

    /// Stores the client identification on the DTLS server-side for the current connection. Must
    /// be stored in [`Context`] first so that it can be set after the `ssl_session_reset` in the
    /// [`establish`](Context::establish) call.
    client_transport_id: Option<Vec<u8>>,
}

impl<'a, T> Into<*const ssl_context> for &'a Context<T> {
    fn into(self) -> *const ssl_context {
        self.handle()
    }
}

impl<'a, T> Into<*mut ssl_context> for &'a mut Context<T> {
    fn into(self) -> *mut ssl_context {
        self.handle_mut()
    }
}

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
            timer_callback: None,
            client_transport_id: None,
        }
    }

    pub(crate) fn handle(&self) -> &::mbedtls_sys::ssl_context {
        self.inner.handle()
    }

    pub(crate) fn handle_mut(&mut self) -> &mut ::mbedtls_sys::ssl_context {
        self.inner.handle_mut()
    }
}

/// # Safety
/// `io` must live as long as `ctx` or the next time bio is set/cleared.
unsafe fn set_bio_raw<IoType, T: IoCallbackUnsafe<IoType>>(ctx: *mut ssl_context, io: &mut T) {
    ssl_set_bio(
        ctx,
        io as *mut T as *mut c_void,
        Some(T::call_send),
        Some(T::call_recv),
        None,
    );
}

/// This function provides a way to apply async context to bio before running 
/// any logic.
/// Note: `bio` is a concept in common TLS implementation which refers to basic IO.
/// openssl and mbedtls both use this concept.
/// Ref: https://stackoverflow.com/questions/51672133/what-are-openssl-bios-how-do-they-work-how-are-bios-used-in-openssl
#[cfg(all(feature = "std", feature = "async"))]
impl<T> Context<T>  {
    pub(super) fn with_bio_async<'cx, R, IoType>(&mut self, cx: &mut std::task::Context<'cx>, f: impl FnOnce(&mut Self) -> R) -> Option<R> where for<'c> (&'c mut std::task::Context<'cx>, &'c mut T): IoCallbackUnsafe<IoType> {
        let ret;

        struct BioGuard<'a, T> {
            context: &'a mut Context<T>,
        }
        
        impl<'a, T> Drop for BioGuard<'a, T> {
            fn drop(&mut self) {
                self.context.clear_bio();
            }
        }
        // SAFETY: In the call to `set_bio_raw`, `user_data` must live as long
        // as `ctx`, or until the bio is cleared from `ctx`. The bio is cleared
        // at the end of this block ensured by the drop guard: [`BioGuard`]
        unsafe {
            // Points to `self.inner`, so safe to borrow at the same time as `self.io`
            let ctx = self.into();
            let mut user_data = (cx, &mut**self.io.as_mut()?);
            set_bio_raw(ctx, &mut user_data);

            let guard = BioGuard { context: self };

            ret = f(guard.context);
        }

        Some(ret)
    }

    // This function is created to handle the odd behavior of `mbedtls_ssl_write()`
    // Please check this https://github.com/Mbed-TLS/mbedtls/issues/4183 to learn more about how `mbedtls_ssl_write()` works in c-mbedtls 2.28
    // This function ultimately ensure the semantics:
    // Returned value `Ok(n)` always means n bytes of data has been sent into c-mbedtls's buffer (some of them might be sent out through underlying IO)
    pub(super) fn async_write(&mut self, buf: &[u8]) -> Result<usize> {
        while self.handle().out_left > 0 {
            self.flush_output()?;
        }
        // when calling `send()` here, already ensured that `ssl_context.out_left` == 0
        match self.send(buf) {
            // Although got `Error::SslWantWrite` means underlying IO is blocked, but some of `buf` is still saved into c-mbedtls's
            // buffer, so we need to return size of bytes that has been buffered.
            // Since we know before this call `out_left` was 0, all buffer (with in the MBEDTLS_SSL_OUT_CONTENT_LEN part) is buffered
            Err(e) if e.high_level() == Some(codes::SslWantWrite) => Ok(std::cmp::min(unsafe { ssl_get_max_out_record_payload((&*self).into()).into_result()? as usize }, buf.len())),
            res => res,
        }
    }
}

impl<T> Context<T> {
    /// Establish a TLS session on the given `io`.
    ///
    /// Upon successful return, the context can be communicated with using the
    /// `std::io::Read` and `std::io::Write` traits if `io` implements those as
    /// well, and using the `mbedtls::ssl::io::Io` trait otherwise.
    pub fn establish<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()> where T: IoCallbackUnsafe<IoType> {
        // SAFETY: In the call to `set_bio_raw`, `self.io` must live as long as
        // `self`, or until the bio is cleared from `ctx`. It lives as long as
        // `self` since it is stored in self and never cleared.
        unsafe {
            self.prepare_handshake(io, hostname)?;
            set_bio_raw(self.into(), &mut**self.io.as_mut().unwrap());
        }
        self.handshake()
    }

    pub(super) fn prepare_handshake(&mut self, io: T, hostname: Option<&str>) -> Result<()> {
        unsafe {
            ssl_session_reset(self.into()).into_result()?;
            self.set_hostname(hostname)?;
            if let Some(client_id) = self.client_transport_id.take() {
                self.set_client_transport_id(&client_id)?;
            }
            self.io = Some(Box::new(io));
            self.inner.reset_handshake();
            Ok(())
        }
    }
}

impl<T> Context<T> {
    /// Try to complete the handshake procedure to set up a (D)TLS connection
    ///
    /// In general, this should not be called directly. Instead, [`establish`](Context::establish)
    /// should be used which properly sets up the [`IoCallbackUnsafe`] and resets any previous sessions.
    ///
    /// This should only be used directly if the handshake could not be completed successfully in
    /// `establish`, i.e.:
    /// - If using non-blocking operation and `establish` failed with [`Error::SslWantRead`] or
    /// [`Error::SslWantWrite`]
    /// - If running a DTLS server and it answers the first `ClientHello` (without cookie) with a
    /// `HelloVerifyRequest`, i.e. `establish` failed with [`Error::SslHelloVerifyRequired`]
    pub fn handshake(&mut self) -> Result<()> {
        match self.inner_handshake() {
            Ok(()) => Ok(()),
            Err(e) if matches!(e.high_level(), Some(codes::SslWantRead | codes::SslWantWrite)) => Err(e),
            Err(e) if matches!(e.high_level(), Some(codes::SslHelloVerifyRequired)) => {
                    unsafe {
                        // `ssl_session_reset` resets the client ID but the user will call handshake
                        // again in this case and the client ID is required for a DTLS connection setup
                        // on the server side. So we extract it before and set it after
                        // `ssl_session_reset`.
                        let mut client_transport_id = None;
                        if !self.inner.handle().cli_id.is_null() {
                            client_transport_id = Some(Vec::from(core::slice::from_raw_parts(self.inner.handle().cli_id, self.inner.handle().cli_id_len)));
                        }
                        ssl_session_reset(self.into()).into_result()?;
                        if let Some(client_id) = client_transport_id.take() {
                            self.set_client_transport_id(&client_id)?;
                        }
                    }
                    Err(codes::SslHelloVerifyRequired.into())
            },
            Err(e) => {
                    self.close();
                    Err(e)
            },
        }
    }

    fn inner_handshake(&mut self) -> Result<()> {
        self.flush_output()?;
        unsafe {
            ssl_handshake(self.into()).into_result_discard()
        }
    }

    pub(super) fn flush_output(&mut self) -> Result<()> {
        unsafe {
            // non-negative return value just means `ssl_flush_output` is succeed
            ssl_flush_output(self.into()).into_result_discard()
        }
    }

    #[cfg(not(feature = "std"))]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        match hostname {
            Some(_) => Err(codes::SslBadInputData.into()),
            None => Ok(()),
        }
    }

    #[cfg(feature = "std")]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        if let Some(s) = hostname {
            let cstr = ::std::ffi::CString::new(s).map_err(|_| Error::from(codes::SslBadInputData))?;
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

    pub(super) fn close_notify(&mut self) -> Result<()> {
        unsafe {
            ssl_close_notify(self.into()).into_result().map(|_| ())
        }
    }

    pub fn close(&mut self) {
        let _ = self.close_notify();
        self.drop_io();
    }

    pub(super) fn clear_bio(&mut self) {
        // It is safe to set the bio to null using the `ssl_set_bio` function. If the bio
        // is null, mbedtls can handle this case and will return an error if you attempt
        // to continue using SSL after calling this function.
        unsafe {
            ssl_set_bio(self.into(), ::core::ptr::null_mut(), None, None, None);
        }
    }
    
    pub(super) fn drop_io(&mut self) {
        self.clear_bio();
        self.io = None;
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
    /// <https://www.iana.org/assignments/tls-parameters/tls-parameters.txt>
    pub fn ciphersuite(&self) -> Result<u16> {
        if self.handle().session.is_null() {
            return Err(codes::SslBadInputData.into());
        }
        
        Ok(unsafe { self.handle().session.as_ref().unwrap().ciphersuite as u16 })
    }

    pub fn peer_cert(&self) -> Result<Option<&MbedtlsList<Certificate>>> {
        if self.handle().session.is_null() {
            return Err(codes::SslBadInputData.into());
        }

        unsafe {
            // We cannot call the peer cert function as we need a pointer to a pointer to create the MbedtlsList, we need something in the heap / cannot use any local variable for that.
            let peer_cert : &MbedtlsList<Certificate> = UnsafeFrom::from(&((*self.handle().session).peer_cert) as *const *mut x509_crt as *const *const x509_crt).ok_or(Error::from(codes::SslBadInputData))?;
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

    pub fn set_timer_callback<F: TimerCallback + 'static>(&mut self, mut cb: Box<F>) {
        unsafe {
            ssl_set_timer_cb(self.into(), cb.data_ptr(), Some(F::set_timer), Some(F::get_timer));
        }
        self.timer_callback = Some(cb);
    }

    /// Set client's transport-level identification info (dtls server only)
    ///
    /// See `mbedtls_ssl_set_client_transport_id`
    fn set_client_transport_id(&mut self, info: &[u8]) -> Result<()> {
        unsafe {
            ssl_set_client_transport_id(self.into(), info.as_ptr(), info.len())
                .into_result()
                .map(|_| ())
        }
    }

    /// Set client's transport-level identification info (dtls server only)
    ///
    /// See `mbedtls_ssl_set_client_transport_id`
    ///
    /// The `info` is used only for the next connection, i.e. it will be used for the next
    /// [`establish`](Context::establish) call. Afterwards, it will be unset again. This is to
    /// ensure that no client identification is accidentally reused if this [`Context`] is reused
    /// for further connections.
    pub fn set_client_transport_id_once(&mut self, info: &[u8]) {
        self.client_transport_id = Some(info.into());
    }

    pub(super) fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            ssl_read(self.into(), buf.as_mut_ptr(), buf.len()).into_result().map(|r| r as usize)
        }
    }

    pub(super) fn send(&mut self, buf: &[u8]) -> Result<usize> {
        unsafe {
            ssl_write(self.into(), buf.as_ptr(), buf.len()).into_result().map(|w| w as usize)
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

//
// Class exists only during SNI callback that is configured from Config.
// SNI Callback must provide input whose lifetime exceeds the SNI closure to avoid memory corruptions.
// That can be achieved easily by storing certificate chains/CRLs inside the closure for the lifetime of the closure.
//
// That is due to SNI being held by an Arc inside Config.
// Config lives longer then Context. Context lives longer then Handshake.
//
// Alternatives are not possible due to:
// - mbedtls not providing any callbacks on handshake finish.
// - no reasonable way to obtain a storage within the sni callback tied to the handshake or to the rust Context. (without resorting to a unscalable map or pointer magic that mbedtls may invalidate)
//
impl HandshakeContext {
    fn reset_handshake(&mut self) {
        self.handshake_cert.clear();
        self.handshake_pk.clear();
        self.handshake_ca_cert = None;
        self.handshake_crl = None;
    }
    
    pub fn set_authmode(&mut self, am: AuthMode) -> Result<()> {
        if self.inner.handshake as *const _ == ::core::ptr::null() {
            return Err(codes::SslBadInputData.into());
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
            return Err(codes::SslBadInputData.into());
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
            return Err(codes::SslBadInputData.into());
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::io::{Read,Write, Result as IoResult};

    use crate::ssl::context::{HandshakeContext, Context};
    use crate::tests::TestTrait;
    
    #[test]
    fn handshake_context_sync() {
        assert!(!TestTrait::<dyn Sync, HandshakeContext>::new().impls_trait(), "HandshakeContext must be !Sync");
    }

    struct NonSendStream {
        _buffer: core::ptr::NonNull<u8>,
    }

    #[cfg(feature = "std")]
    impl Read for NonSendStream {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            unimplemented!()
        }
    }
    
    #[cfg(feature = "std")]
    impl Write for NonSendStream {
        fn write(&mut self, _: &[u8]) -> IoResult<usize> {
            unimplemented!()
        }

        fn flush(&mut self) -> IoResult<()> {
            unimplemented!()
        }
    }

    struct SendStream {
        _buffer: u8,
    }

    #[cfg(feature = "std")]
    impl Read for SendStream {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            unimplemented!()
        }
    }
    
    #[cfg(feature = "std")]
    impl Write for SendStream {
        fn write(&mut self, _: &[u8]) -> IoResult<usize> {
            unimplemented!()
        }

        fn flush(&mut self) -> IoResult<()> {
            unimplemented!()
        }
    }

    #[test]
    fn context_send() {
        assert!(!TestTrait::<dyn Send, NonSendStream>::new().impls_trait(), "NonSendStream can't be send");
        assert!(!TestTrait::<dyn Send, Context<NonSendStream>>::new().impls_trait(), "Context<NonSendStream> can't be send");

        assert!(TestTrait::<dyn Send, SendStream>::new().impls_trait(), "SendStream is send");
        assert!(TestTrait::<dyn Send, Context<SendStream>>::new().impls_trait(), "Context<SendStream> is send");
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
