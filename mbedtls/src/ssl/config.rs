/*
 * Rust interface for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use mbedtls_sys::types::raw_types::{c_char,c_int};
use mbedtls_sys::*;

use error::IntoResult;
use x509::{LinkedCertificate,Crl,Profile};

define!(enum Endpoint -> c_int {
	Client => SSL_IS_CLIENT,
	Server => SSL_IS_SERVER,
});

define!(enum Transport -> c_int {
	/// TLS
	Stream => SSL_TRANSPORT_STREAM,
	/// DTLS
	Datagram => SSL_TRANSPORT_DATAGRAM,
});

define!(enum Preset -> c_int {
	Default => SSL_PRESET_DEFAULT,
	SuiteB => SSL_PRESET_SUITEB,
});

define!(enum AuthMode -> c_int {
	/// **INSECURE** on client, default on server
	None => SSL_VERIFY_NONE,
	/// **INSECURE**
	Optional => SSL_VERIFY_OPTIONAL,
	/// default on client
	Required => SSL_VERIFY_REQUIRED,
});

callback!(DbgCallback:Sync(level: c_int, file: *const c_char, line: c_int, message: *const c_char) -> ());

define!(struct Config<'c>(ssl_config) {
	fn init = ssl_config_init;
	fn drop = ssl_config_free;
	impl<'q> Into<*>;
});

#[cfg(feature="threading")]
unsafe impl<'c> Sync for Config<'c> {}

impl<'c> Config<'c> {
	pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
		let mut c=Config::init();
		unsafe{ssl_config_defaults(&mut c.inner,e.into(),t.into(),p.into());}
		c
	}
	
	// needs bitfield support: getter!(endpoint() -> Endpoint = field endpoint);
	setter!(set_endpoint(e: Endpoint) = ssl_conf_endpoint);
	// needs bitfield support: getter!(transport() -> Transport = field transport);
	setter!(set_transport(t: Transport) = ssl_conf_transport);
	// needs bitfield support: getter!(authmode() -> AuthMode = field authmode);
	setter!(set_authmode(am: AuthMode) = ssl_conf_authmode);
	getter!(read_timeout() -> u32 = .read_timeout);
	setter!(set_read_timeout(t: u32) = ssl_conf_read_timeout);

	fn check_ciphersuites(list: &[c_int]) {
		assert!(list.last()==Some(&0));
	}

	pub fn set_ciphersuites(&mut self, list: &'c [c_int]) {
		Self::check_ciphersuites(list);
		unsafe{ssl_conf_ciphersuites(&mut self.inner,list.as_ptr())}
	}

	pub fn set_ciphersuites_for_version(&mut self, list: &'c [c_int], major: c_int, minor: c_int) {
		Self::check_ciphersuites(list);
		unsafe{ssl_conf_ciphersuites_for_version(&mut self.inner,list.as_ptr(),major,minor)}
	}

	setter!(set_cert_profile(p: &'c Profile) = ssl_conf_cert_profile);
	
	pub fn set_ca_list<C: Into<&'c mut LinkedCertificate>>(&mut self, list: Option<C>, crl: Option<&'c mut Crl>) {
		unsafe{ssl_conf_ca_chain(
			&mut self.inner,
			list.map(Into::into).map(Into::into).unwrap_or(::core::ptr::null_mut()),
			crl.map(Into::into).unwrap_or(::core::ptr::null_mut())
		)}
	}
	
	pub fn push_cert<C: Into<&'c mut LinkedCertificate>>(&mut self, chain: C, key: &'c mut ::pk::Pk) -> ::Result<()> {
		unsafe{ssl_conf_own_cert(&mut self.inner,chain.into().into(),key.into()).into_result().map(|_|())}
	}
}

setter_callback!(Config<'c>::set_rng(f: ::rng::Random) = ssl_conf_rng);
setter_callback!(Config<'c>::set_dbg(f: DbgCallback) = ssl_conf_dbg);

/*
TODO
ssl_conf_verify
ssl_conf_session_tickets_cb
ssl_conf_export_keys_cb
ssl_conf_dtls_cookies
ssl_conf_dtls_anti_replay
ssl_conf_dtls_badmac_limit
ssl_conf_handshake_timeout
ssl_conf_session_cache
ssl_conf_psk
ssl_conf_psk_cb
ssl_conf_dh_param
ssl_conf_dh_param_ctx
ssl_conf_dhm_min_bitlen
ssl_conf_curves
ssl_conf_sig_hashes
ssl_conf_sni
ssl_conf_alpn_protocols
ssl_conf_max_version
ssl_conf_min_version
ssl_conf_fallback
ssl_conf_encrypt_then_mac
ssl_conf_extended_master_secret
ssl_conf_arc4_support
ssl_conf_max_frag_len
ssl_conf_truncated_hmac
ssl_conf_cbc_record_splitting
ssl_conf_session_tickets
ssl_conf_renegotiation
ssl_conf_legacy_renegotiation
ssl_conf_renegotiation_enforced
ssl_conf_renegotiation_period
*/
