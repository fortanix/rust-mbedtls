/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(feature = "std")]
use std::borrow::Cow;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::slice::from_raw_parts;

use mbedtls_sys::types::raw_types::*;
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use crate::alloc::List as MbedtlsList;
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::error::{Error, IntoResult, Result};
use crate::pk::dhparam::Dhm;
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::rng::RngCallback;
use crate::ssl::context::HandshakeContext;
use crate::ssl::cookie::CookieCallback;
use crate::ssl::ticket::TicketCallback;
use crate::x509::{self, Certificate, Crl, Profile, VerifyCallback};

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum Version {
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
}

define!(
    #[c_ty(c_int)]
    enum Endpoint {
        Client = SSL_IS_CLIENT,
        Server = SSL_IS_SERVER,
    }
);

define!(
    #[c_ty(c_int)]
    #[derive(PartialEq, Eq)]
    enum Transport {
        /// TLS
        Stream = SSL_TRANSPORT_STREAM,
        /// DTLS
        Datagram = SSL_TRANSPORT_DATAGRAM,
    }
);

define!(
    #[c_ty(c_int)]
    enum Preset {
        Default = SSL_PRESET_DEFAULT,
        SuiteB = SSL_PRESET_SUITEB,
    }
);

define!(
    #[c_ty(c_int)]
    enum AuthMode {
        /// **INSECURE** on client, default on server
        None = SSL_VERIFY_NONE,
        /// **INSECURE**
        Optional = SSL_VERIFY_OPTIONAL,
        /// default on client
        Required = SSL_VERIFY_REQUIRED,
    }
);

define!(
    #[c_ty(c_int)]
    enum UseSessionTickets {
        Enabled = SSL_SESSION_TICKETS_ENABLED,
        Disabled = SSL_SESSION_TICKETS_DISABLED,
    }
);

define!(
    #[c_ty(c_int)]
    enum Renegotiation {
        Enabled = SSL_RENEGOTIATION_ENABLED,
        Disabled = SSL_RENEGOTIATION_DISABLED,
    }
);

#[cfg(feature = "std")]
callback!(DbgCallback: Fn(i32, Cow<'_, str>, i32, Cow<'_, str>));
callback!(SniCallback: Fn(&mut HandshakeContext, &[u8]) -> Result<()>);
callback!(CaCallback: Fn(&MbedtlsList<Certificate>) -> Result<MbedtlsList<Certificate>>);

#[repr(transparent)]
pub struct NullTerminatedStrList {
    c: Vec<*mut c_char>,
}

unsafe impl Send for NullTerminatedStrList {}
unsafe impl Sync for NullTerminatedStrList {}

impl NullTerminatedStrList {
    #[cfg(feature = "std")]
    pub fn new(list: &[&str]) -> Result<Self> {
        let mut ret = Self {
            c: Vec::with_capacity(list.len() + 1),
        };

        for item in list {
            ret.c.push(
                ::std::ffi::CString::new(*item)
                    .map_err(|_| Error::SslBadInputData)?
                    .into_raw(),
            );
        }

        ret.c.push(core::ptr::null_mut());
        Ok(ret)
    }

    #[must_use]
    pub fn as_ptr(&self) -> *const *const c_char {
        self.c.as_ptr() as *const _
    }
}

#[cfg(feature = "std")]
impl Drop for NullTerminatedStrList {
    fn drop(&mut self) {
        for i in &self.c {
            unsafe {
                if !(*i).is_null() {
                    let _ = ::std::ffi::CString::from_raw(*i);
                }
            }
        }
    }
}

define!(
    #[c_ty(ssl_config)]
    #[repr(C)]
    struct Config {
        // Holding reference counters against any structures that ssl_config might hold pointer to.
        // This allows caller to share structure on multiple configs if needed.
        own_cert: Vec<Arc<MbedtlsList<Certificate>>>,
        own_pk: Vec<Arc<Pk>>,

        ca_cert: Option<Arc<MbedtlsList<Certificate>>>,
        crl: Option<Arc<Crl>>,

        rng: Option<Arc<dyn RngCallback + 'static>>,

        ciphersuites: Vec<Arc<Vec<c_int>>>,
        curves: Option<Arc<Vec<ecp_group_id>>>,
        protocols: Option<Arc<NullTerminatedStrList>>,

        verify_callback: Option<Arc<dyn VerifyCallback + 'static>>,
        #[cfg(feature = "std")]
        dbg_callback: Option<Arc<dyn DbgCallback + 'static>>,
        sni_callback: Option<Arc<dyn SniCallback + 'static>>,
        ticket_callback: Option<Arc<dyn TicketCallback + 'static>>,
        ca_callback: Option<Arc<dyn CaCallback + 'static>>,
        dtls_cookies: Option<Arc<dyn CookieCallback + 'static>>,
    };
    const drop: fn(&mut Self) = ssl_config_free;
    impl<'a> Into<ptr> {}
);

unsafe impl Sync for Config {}

impl Config {
    #[must_use]
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut inner = ssl_config::default();

        unsafe {
            // This is just a memset to 0.
            ssl_config_init(&mut inner);

            // Set default values - after this point we will need ssl_config_free to be
            // called.
            ssl_config_defaults(&mut inner, e as c_int, t as c_int, p as c_int);
        };

        Self {
            inner,
            own_cert: vec![],
            own_pk: vec![],
            ca_cert: None,
            crl: None,
            rng: None,
            ciphersuites: vec![],
            curves: None,
            protocols: None,
            verify_callback: None,
            #[cfg(feature = "std")]
            dbg_callback: None,
            sni_callback: None,
            ticket_callback: None,
            ca_callback: None,
            dtls_cookies: None,
        }
    }

    // need bitfield support getter!(endpoint() -> Endpoint = field endpoint);
    setter!(set_endpoint(e: Endpoint) = ssl_conf_endpoint);
    // need bitfield support getter!(transport() -> Transport = field transport);
    setter!(set_transport(t: Transport) = ssl_conf_transport);
    // need bitfield support getter!(authmode() -> AuthMode = field authmode);
    setter!(set_authmode(am: AuthMode) = ssl_conf_authmode);
    getter!(read_timeout() -> u32 = .read_timeout);
    setter!(set_read_timeout(t: u32) = ssl_conf_read_timeout);

    fn check_c_list<T: Default + Eq>(list: &[T]) {
        assert!(list.last() == Some(&T::default()));
    }

    pub fn set_ciphersuites(&mut self, list: Arc<Vec<c_int>>) {
        Self::check_c_list(&list);

        unsafe { ssl_conf_ciphersuites(self.into(), list.as_ptr()) }
        self.ciphersuites.push(list);
    }

    /// Set the supported Application Layer Protocols.
    pub fn set_alpn_protocols(&mut self, protocols: Arc<NullTerminatedStrList>) -> Result<()> {
        unsafe {
            ssl_conf_alpn_protocols(&mut self.inner, protocols.as_ptr() as *mut _)
                .into_result()
                .map(|_| ())?;
        }

        self.protocols = Some(protocols);
        Ok(())
    }

    pub fn set_ciphersuites_for_version(&mut self, list: Arc<Vec<c_int>>, major: c_int, minor: c_int) {
        Self::check_c_list(&list);
        unsafe { ssl_conf_ciphersuites_for_version(self.into(), list.as_ptr(), major, minor) }
        self.ciphersuites.push(list);
    }

    pub fn set_curves(&mut self, list: Arc<Vec<ecp_group_id>>) {
        Self::check_c_list(&list);
        unsafe { ssl_conf_curves(self.into(), list.as_ptr()) }
        self.curves = Some(list);
    }

    pub fn set_rng<T: RngCallback + 'static>(&mut self, rng: Arc<T>) {
        unsafe { ssl_conf_rng(self.into(), Some(T::call), rng.data_ptr()) };
        self.rng = Some(rng);
    }

    pub fn set_min_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
        };

        unsafe { ssl_conf_min_version(self.into(), 3, minor) };
        Ok(())
    }

    pub fn set_max_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
        };
        unsafe { ssl_conf_max_version(self.into(), 3, minor) };
        Ok(())
    }

    // Profile as implemented in profile.rs can only point to global variables from
    // mbedtls which would have 'static lifetime
    setter!(set_cert_profile(p: &'static Profile) = ssl_conf_cert_profile);

    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub fn set_dh_params(&mut self, dhm: &Dhm) -> Result<()> {
        unsafe {
            // This copies the dhm parameters and does not store any pointer to it
            ssl_conf_dh_param_ctx(self.into(), dhm.inner_ffi_mut())
                .into_result()
                .map(|_| ())?;
        }
        Ok(())
    }

    pub fn set_ca_list(&mut self, ca_cert: Arc<MbedtlsList<Certificate>>, crl: Option<Arc<Crl>>) {
        // This will override internal pointers to what we provide.

        unsafe {
            ssl_conf_ca_chain(
                self.into(),
                ca_cert.inner_ffi_mut(),
                crl.as_ref().map_or(::core::ptr::null_mut(), |crl| crl.inner_ffi_mut()),
            );
        }

        self.ca_cert = Some(ca_cert);
        self.crl = crl;
    }

    pub fn push_cert(&mut self, own_cert: Arc<MbedtlsList<Certificate>>, own_pk: Arc<Pk>) -> Result<()> {
        if own_cert.is_empty() {
            return Err(Error::SslBadInputData);
        }
        // Need to ensure own_cert/pk_key outlive the config.
        self.own_cert.push(own_cert.clone());
        self.own_pk.push(own_pk.clone());

        // This will append pointers to our certificates inside mbedtls
        unsafe {
            ssl_conf_own_cert(self.into(), own_cert.inner_ffi_mut(), own_pk.inner_ffi_mut())
                .into_result()
                .map(|_| ())
        }
    }

    /// Server only: configure callback to use for generating/interpreting
    /// session tickets.
    pub fn set_session_tickets_callback<T: TicketCallback + 'static>(&mut self, cb: Arc<T>) {
        unsafe { ssl_conf_session_tickets_cb(self.into(), Some(T::call_write), Some(T::call_parse), cb.data_ptr()) };

        self.ticket_callback = Some(cb);
    }

    setter!(
        /// Client only: whether to remember and use session tickets
        set_session_tickets(u: UseSessionTickets) = ssl_conf_session_tickets
    );

    setter!(set_renegotiation(u: Renegotiation) = ssl_conf_renegotiation);

    setter!(
        /// Client only: minimal FFDH group size
        set_ffdh_min_bitlen(bitlen: c_uint) = ssl_conf_dhm_min_bitlen
    );

    pub fn set_sni_callback<F>(&mut self, cb: F)
    where
        F: SniCallback + 'static,
    {
        unsafe extern "C" fn sni_callback<F>(
            closure: *mut c_void,
            ctx: *mut ssl_context,
            name: *const c_uchar,
            name_len: size_t,
        ) -> c_int
        where
            F: Fn(&mut HandshakeContext, &[u8]) -> Result<()> + 'static,
        {
            // This is called from:
            //
            // mbedtls/src/ssl/context.rs           - establish
            // mbedtls-sys/vendor/library/ssl_tls.c - mbedtls_ssl_handshake
            // mbedtls-sys/vendor/library/ssl_tls.c - mbedtls_ssl_handshake_step
            // mbedtls-sys/vendor/library/ssl_srv.c - mbedtls_ssl_handshake_server_step
            // mbedtls-sys/vendor/library/ssl_srv.c - ssl_parse_client_hello
            // mbedtls-sys/vendor/library/ssl_srv.c - ssl_parse_servername_ext
            //
            // As such:
            // - The ssl_context is a rust 'Context' structure that we have a mutable
            //   reference to via 'establish'
            // - We can pointer cast to it to allow storing additional objects.
            //
            let cb = &mut *(closure as *mut F);
            let ctx = UnsafeFrom::from(ctx).unwrap();

            let name = from_raw_parts(name, name_len);
            match cb(ctx, name) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }

        self.sni_callback = Some(Arc::new(cb));
        unsafe {
            ssl_conf_sni(
                self.into(),
                Some(sni_callback::<F>),
                &**self.sni_callback.as_mut().unwrap() as *const _ as *mut c_void,
            );
        }
    }

    // The docs for mbedtls_x509_crt_verify say "The [callback] should return 0 for
    // anything but a fatal error.", so verify callbacks should return Ok(())
    // for anything but a fatal error. Report verification errors by updating
    // the flags in VerifyError.
    pub fn set_verify_callback<F>(&mut self, cb: F)
    where
        F: VerifyCallback + 'static,
    {
        self.verify_callback = Some(Arc::new(cb));
        unsafe {
            ssl_conf_verify(
                self.into(),
                Some(x509::verify_callback::<F>),
                &**self.verify_callback.as_ref().unwrap() as *const _ as *mut c_void,
            );
        }
    }

    pub fn set_ca_callback<F>(&mut self, cb: F)
    where
        F: CaCallback + 'static,
    {
        unsafe extern "C" fn ca_callback<F>(
            closure: *mut c_void,
            child: *const x509_crt,
            candidate_cas: *mut *mut x509_crt,
        ) -> c_int
        where
            F: CaCallback + 'static,
        {
            if child.is_null() || closure.is_null() || candidate_cas.is_null() {
                return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA;
            }

            let cb = &mut *(closure as *mut F);
            let crt: &MbedtlsList<Certificate> = UnsafeFrom::from(&child as *const *const x509_crt).expect("valid certificate");
            match cb(crt) {
                Ok(list) => {
                    // This does not leak due to mbedtls taking ownership from us and freeing the
                    // certificates itself. (logic is in:
                    // mbedtls-sys/vendor/library/x509_crt.c:2904)
                    *candidate_cas = list.into_raw();
                    0
                }
                Err(e) => e.to_int(),
            }
        }

        self.ca_callback = Some(Arc::new(cb));
        unsafe {
            ssl_conf_ca_cb(
                self.into(),
                Some(ca_callback::<F>),
                &**self.ca_callback.as_mut().unwrap() as *const _ as *mut c_void,
            );
        }
    }

    #[cfg(feature = "std")]
    pub fn set_dbg_callback<F>(&mut self, cb: F)
    where
        F: DbgCallback + 'static,
    {
        #[allow(dead_code)]
        unsafe extern "C" fn dbg_callback<F>(
            closure: *mut c_void,
            level: c_int,
            file: *const c_char,
            line: c_int,
            message: *const c_char,
        ) where
            F: DbgCallback + 'static,
        {
            let cb = &mut *(closure as *mut F);

            let file = match file.is_null() {
                false => std::ffi::CStr::from_ptr(file).to_string_lossy(),
                true => Cow::from(""),
            };

            let message = match message.is_null() {
                false => std::ffi::CStr::from_ptr(message).to_string_lossy(),
                true => Cow::from(""),
            };

            cb(level, file, line, message);
        }

        self.dbg_callback = Some(Arc::new(cb));
        unsafe {
            ssl_conf_dbg(
                self.into(),
                Some(dbg_callback::<F>),
                &**self.dbg_callback.as_mut().unwrap() as *const _ as *mut c_void,
            );
        }
    }

    /// Sets the PSK and the PSK-Identity
    ///
    /// Only a single entry is supported at the moment. If another one was set
    /// before, it will be overridden.
    pub fn set_psk(&mut self, psk: &[u8], psk_identity: &str) -> Result<()> {
        unsafe {
            // This allocates and copies the buffers and does not store any pointer to them
            ssl_conf_psk(
                self.into(),
                psk.as_ptr(),
                psk.len(),
                psk_identity.as_ptr(),
                psk_identity.len(),
            )
            .into_result()
            .map(|_| ())
        }
    }

    /// Sets the cookie context and callbacks which are required for DTLS
    /// servers
    pub fn set_dtls_cookies<T: CookieCallback + 'static>(&mut self, dtls_cookies: Arc<T>) {
        unsafe {
            ssl_conf_dtls_cookies(
                self.into(),
                Some(T::cookie_write),
                Some(T::cookie_check),
                dtls_cookies.data_ptr(),
            );
        };
        self.dtls_cookies = Some(dtls_cookies);
    }
}

// TODO
// ssl_conf_export_keys_cb
// ssl_conf_dtls_cookies
// ssl_conf_dtls_anti_replay
// ssl_conf_dtls_badmac_limit
// ssl_conf_handshake_timeout
// ssl_conf_session_cache
// ssl_conf_psk_cb
// ssl_conf_sig_hashes
// ssl_conf_alpn_protocols
// ssl_conf_fallback
// ssl_conf_encrypt_then_mac
// ssl_conf_extended_master_secret
// ssl_conf_arc4_support
// ssl_conf_max_frag_len
// ssl_conf_truncated_hmac
// ssl_conf_cbc_record_splitting
// ssl_conf_renegotiation
// ssl_conf_legacy_renegotiation
// ssl_conf_renegotiation_enforced
// ssl_conf_renegotiation_period
//
