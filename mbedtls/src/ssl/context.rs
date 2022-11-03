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
    std::io::{Read, Write, Result as IoResult, Error as IoError},
    std::sync::Arc,
};

#[cfg(not(feature = "std"))]
use core_io::{Read, Write, Result as IoResult};


use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::alloc::{List as MbedtlsList};
use crate::error::{Error, Result, IntoResult};
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::ssl::config::{Config, Version, AuthMode};
use crate::x509::{Certificate, Crl, VerifyError};

pub trait IoCallback {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int where Self: Sized;
    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int where Self: Sized;
    fn data_ptr(&mut self) -> *mut c_void;
}

impl<IO: Read + Write> IoCallback for IO {
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

#[cfg(feature = "std")]
pub struct ConnectedUdpSocket {
    socket: std::net::UdpSocket,
}

#[cfg(feature = "std")]
impl ConnectedUdpSocket {
    pub fn connect<A: std::net::ToSocketAddrs>(socket: std::net::UdpSocket, addr: A) -> StdResult<Self, (IoError, std::net::UdpSocket)> {
        match socket.connect(addr) {
            Ok(_) => Ok(ConnectedUdpSocket {
                socket,
            }),
            Err(e) => Err((e, socket)),
        }
    }
}

#[cfg(feature = "std")]
impl IoCallback for ConnectedUdpSocket {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut ConnectedUdpSocket)).socket.recv(::core::slice::from_raw_parts_mut(data, len)) {
            Ok(i) => i as c_int,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(_) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
        }
    }

    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut ConnectedUdpSocket)).socket.send(::core::slice::from_raw_parts(data, len)) {
            Ok(i) => i as c_int,
            Err(_) => ::mbedtls_sys::ERR_NET_SEND_FAILED,
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut ConnectedUdpSocket as *mut c_void
    }
}

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
            ssl_setup(&mut inner, (&*config).into()).into_result().unwrap();
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

impl<T: IoCallback> Context<T> {
    pub fn establish(&mut self, io: T, hostname: Option<&str>) -> Result<()> {
        unsafe {
            let mut io = Box::new(io);
            ssl_session_reset(self.into()).into_result()?;
            self.set_hostname(hostname)?;
            if let Some(client_id) = self.client_transport_id.take() {
                self.set_client_transport_id(&client_id)?;
            }

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
    /// Try to complete the handshake procedure to set up a (D)TLS connection
    ///
    /// In general, this should not be called directly. Instead, [`establish`](Context::establish)
    /// should be used which properly sets up the [`IoCallback`] and resets any previous sessions.
    ///
    /// This should only be used directly if the handshake could not be completed successfully in
    /// `establish`, i.e.:
    /// - If using nonblocking operation and `establish` failed with [`Error::SslWantRead`] or
    /// [`Error::SslWantWrite`]
    /// - If running a DTLS server and it answers the first `ClientHello` (without cookie) with a
    /// `HelloVerifyRequest`, i.e. `establish` failed with [`Error::SslHelloVerifyRequired`]
    pub fn handshake(&mut self) -> Result<()> {
        match self.inner_handshake() {
            Ok(()) => Ok(()),
            Err(Error::SslWantRead) => Err(Error::SslWantRead),
            Err(Error::SslWantWrite) => Err(Error::SslWantWrite),
            Err(Error::SslHelloVerifyRequired) => {
                unsafe {
                    // `ssl_session_reset` resets the client ID but the user will call handshake
                    // again in this case and the client ID is required for a DTLS connection setup
                    // on the server side. So we extract it before and set it after
                    // `ssl_session_reset`.
                    let mut client_transport_id = None;
                    if !self.inner.handle().private_cli_id.is_null() {
                        client_transport_id = Some(Vec::from(core::slice::from_raw_parts(self.inner.handle().private_cli_id, self.inner.handle().private_cli_id_len)));
                    }
                    ssl_session_reset(self.into()).into_result()?;
                    if let Some(client_id) = client_transport_id.take() {
                        self.set_client_transport_id(&client_id)?;
                    }
                }
                Err(Error::SslHelloVerifyRequired)
            }
            Err(e) => {
                self.close();
                Err(e)
            },
        }
    }

    fn inner_handshake(&mut self) -> Result<()> {
        unsafe {
            ssl_handshake(self.into()).into_result_discard()
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



    /// Return the number of bytes currently available to read that
    /// are stored in the Session's internal read buffer
    pub fn bytes_available(&self) -> usize {
        unsafe { ssl_get_bytes_avail(self.into()) }
    }

    pub fn version(&self) -> Version {
        match self.handle().private_tls_version {
            SSL_VERSION_TLS1_2 => Version::Tls1_2,
            SSL_VERSION_TLS1_3 => Version::Tls1_3,
            SSL_VERSION_UNKNOWN => Version::Unknown,
            _ => unreachable!("unexpected TLS version")
        }
    }


    // Session specific functions

    /// Return the 16-bit ciphersuite identifier.
    /// All assigned ciphersuites are listed by the IANA in
    /// <https://www.iana.org/assignments/tls-parameters/tls-parameters.txt>
    pub fn ciphersuite(&self) -> Result<u16> {
        if self.handle().private_session.is_null() {
            return Err(Error::SslBadInputData);
        }

        Ok(unsafe { self.handle().private_session.as_ref().unwrap().private_ciphersuite as u16 })
    }

    pub fn peer_cert(&self) -> Result<Option<&MbedtlsList<Certificate>>> {
        if self.handle().private_session.is_null() {
            return Err(Error::SslBadInputData);
        }

        unsafe {
            // We cannot call the peer cert function as we need a pointer to a pointer to create the MbedtlsList, we need something in the heap / cannot use any local variable for that.
            let peer_cert : &MbedtlsList<Certificate> = UnsafeFrom::from(&((*self.handle().private_session).private_peer_cert) as *const *mut x509_crt as *const *const x509_crt).ok_or(Error::SslBadInputData)?;
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
}

impl<T> Drop for Context<T> {
    fn drop(&mut self) {
        unsafe {
            self.close();
            ssl_free(self.into());
        }
    }
}

impl<T: IoCallback> Read for Context<T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match unsafe { ssl_read(self.into(), buf.as_mut_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }
}

impl<T: IoCallback> Write for Context<T> {
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
// SNI Callback must provide input whose lifetime exceeds the SNI closure to avoid memory corruptions.
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
    fn reset_handshake(&mut self) {
        self.handshake_cert.clear();
        self.handshake_pk.clear();
        self.handshake_ca_cert = None;
        self.handshake_crl = None;
    }

    pub fn set_authmode(&mut self, am: AuthMode) -> Result<()> {
        if self.inner.private_handshake as *const _ == ::core::ptr::null() {
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
        if self.inner.private_handshake as *const _ == ::core::ptr::null() {
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
        if self.inner.private_handshake as *const _ == ::core::ptr::null() {
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::io::{Read,Write, Result as IoResult};

    #[cfg(not(feature = "std"))]
    use core_io::{Read, Write, Result as IoResult};

    use crate::ssl::context::{HandshakeContext, Context};
    use crate::tests::TestTrait;

    #[test]
    fn handshakecontext_sync() {
        assert!(!TestTrait::<dyn Sync, HandshakeContext>::new().impls_trait(), "HandshakeContext must be !Sync");
    }

    struct NonSendStream {
        _buffer: core::ptr::NonNull<u8>,
    }

    impl Read for NonSendStream {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            unimplemented!()
        }
    }

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

    impl Read for SendStream {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            unimplemented!()
        }
    }

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
