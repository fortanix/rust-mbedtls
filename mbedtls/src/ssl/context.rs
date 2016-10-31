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

#[cfg(feature="std")]
use std::io::{Read,Write,self};
#[cfg(not(feature="std"))]
use core_io::{Read,Write,self as io};

use mbedtls_sys::types::raw_types::{c_int,c_uchar,c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use error::IntoResult;
use ssl::Config;

pub trait IoCallback {
	unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int;
	unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int;
	
	fn data_ptr(&mut self) -> *mut c_void;
}

impl<IO: Read + Write> IoCallback for IO {
	unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
		let len=if len>(c_int::max_value() as size_t) { c_int::max_value() as size_t } else { len };
		match (&mut*(user_data as *mut IO)).read(::core::slice::from_raw_parts_mut(data,len)) {
			Ok(i) => i as c_int,
			Err(_) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
		}
	}

	unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
		let len=if len>(c_int::max_value() as size_t) { c_int::max_value() as size_t } else { len };
		match (&mut*(user_data as *mut IO)).write(::core::slice::from_raw_parts(data,len)) {
			Ok(i) => i as c_int,
			Err(_) => ::mbedtls_sys::ERR_NET_SEND_FAILED,
		}
	}

	fn data_ptr(&mut self) -> *mut c_void {
		self as *mut IO as *mut _
	}
}

define!(struct Context<'config>(ssl_context) {
	fn init = ssl_init;
	fn drop = ssl_free;
});

pub struct Session<'ctx> {
	inner: &'ctx mut ssl_context
}

#[cfg(feature="threading")]
unsafe impl<'ctx> Send for Session<'ctx> {}

impl<'config> Context<'config> {
	pub fn new(config: &'config Config) -> ::Result<Context<'config>> {
		let mut ret=Self::init();
		unsafe{ssl_setup(&mut ret.inner,config.into())}.into_result().map(|_|ret)
	}
	
	pub fn establish<'c,F: IoCallback>(&'c mut self,io: &'c mut F) -> ::Result<Session<'c>> {
		unsafe {
			try!(ssl_session_reset(&mut self.inner).into_result());
			ssl_set_bio(&mut self.inner,io.data_ptr(),Some(F::call_send),Some(F::call_recv),None);
			match ssl_handshake(&mut self.inner).into_result() {
				Err(e) => {
					// safely end borrow of io
					ssl_set_bio(&mut self.inner,::core::ptr::null_mut(),None,None,None);
					Err(e)
				}
				Ok(_) => Ok(Session{inner:&mut self.inner})
			}
		}
	}
}

impl<'a> Session<'a> {
	pub fn peer_cert(&self) -> Option<&::x509::LinkedCertificate> {
		unsafe{::private::UnsafeFrom::from(ssl_get_peer_cert(self.inner))}
	}
}

impl<'a> Read for Session<'a> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match unsafe{ssl_read(self.inner,buf.as_mut_ptr(),buf.len()).into_result()} {
			Err(::Error::SslPeerCloseNotify) => Ok(0),
			Err(e) => Err(::private::error_to_io_error(e)),
			Ok(i) => Ok(i as usize),
		}
	}
}

impl<'a> Write for Session<'a> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match unsafe{ssl_write(self.inner,buf.as_ptr(),buf.len()).into_result()} {
			Err(::Error::SslPeerCloseNotify) => Ok(0),
			Err(e) => Err(::private::error_to_io_error(e)),
			Ok(i) => Ok(i as usize),
		}
	}

	fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<'a> Drop for Session<'a> {
	fn drop(&mut self) {
		unsafe {
			ssl_close_notify(self.inner);
			ssl_set_bio(self.inner,::core::ptr::null_mut(),None,None,None);
		}
	}
}

/* 
TODO
ssl_get_alpn_protocol
ssl_get_bytes_avail
ssl_get_max_frag_len
ssl_get_record_expansion
ssl_get_verify_result
ssl_get_version
ssl_renegotiate
ssl_send_alert_message
ssl_set_client_transport_id
ssl_set_hostname
ssl_set_hs_authmode
ssl_set_hs_ca_chain
ssl_set_hs_own_cert
ssl_set_hs_psk
ssl_set_timer_cb

ssl_handshake_step
*/
/*
CLIENT SIDE SESSIONS
ssl_session_free
ssl_session_init
ssl_get_session
ssl_set_session
*/
/*
SERVER SIDE SESSIONS (ssl_conf_session_cache)
ssl_cache_free
ssl_cache_get
ssl_cache_init
ssl_cache_set
ssl_cache_set_max_entries
*/
/*
CIPHER SUITES
ssl_ciphersuite_from_id
ssl_ciphersuite_from_string
ssl_ciphersuite_uses_ec
ssl_ciphersuite_uses_psk
ssl_get_ciphersuite_id
ssl_get_ciphersuite_name
ssl_get_ciphersuite_sig_pk_alg
ssl_list_ciphersuites
*/
/*
TICKETS (mbedtls_ssl_conf_session_tickets_cb)
ssl_ticket_free
ssl_ticket_init
ssl_ticket_parse
ssl_ticket_setup
ssl_ticket_write
*/
/*
DTLS SERVER COOKIES (ssl_conf_dtls_cookies)
ssl_cookie_check
ssl_cookie_free
ssl_cookie_init
ssl_cookie_set_timeout
ssl_cookie_setup
ssl_cookie_write
 */
/*
INTERNAL
ssl_check_cert_usage
ssl_check_curve
ssl_check_sig_hash
ssl_derive_keys
ssl_dtls_replay_check
ssl_dtls_replay_update
ssl_fetch_input
ssl_flush_output
ssl_handshake_client_step
ssl_handshake_free
ssl_handshake_server_step
ssl_handshake_wrapup
ssl_hash_from_md_alg
ssl_md_alg_from_hash
ssl_optimize_checksum
ssl_parse_certificate
ssl_parse_change_cipher_spec
ssl_parse_finished
ssl_pk_alg_from_sig
ssl_psk_derive_premaster
ssl_read_record
ssl_read_version
ssl_recv_flight_completed
ssl_resend
ssl_reset_checksum
ssl_send_fatal_handshake_failure
ssl_send_flight_completed
ssl_sig_from_pk
ssl_transform_free
ssl_write_certificate
ssl_write_change_cipher_spec
ssl_write_finished
ssl_write_record
ssl_write_version
*/
