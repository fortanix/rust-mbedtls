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

extern crate mbedtls;
extern crate mbedtls_sys;

macro_rules! tests {
	{ $($(#[$m:meta])* fn $t:ident,)*} => {
		$(
		#[test]
		$(#[$m])*
		fn $t() {
			unsafe {
				assert!(mbedtls_sys::$t(1)==0);
			}
		}
		)*
	};
}

tests!{
	fn aes_self_test,
	fn arc4_self_test,
	fn base64_self_test,
	fn camellia_self_test,
	fn ccm_self_test,
	fn ctr_drbg_self_test,
	fn des_self_test,
	fn dhm_self_test,
	#[cfg(feature="std")]
	fn entropy_self_test,
	fn gcm_self_test,
	fn hmac_drbg_self_test,
	fn md2_self_test,
	fn md4_self_test,
	fn md5_self_test,
	fn mpi_self_test,
	fn pkcs5_self_test,
	fn ripemd160_self_test,
	fn rsa_self_test,
	fn sha1_self_test,
	fn sha256_self_test,
	fn sha512_self_test,
	fn x509_self_test,
	fn xtea_self_test,
}

// these can't run concurrently
#[test]
fn ec_self_tests() {
	unsafe {
		assert!(mbedtls_sys::ecp_self_test(1)==0);
		assert!(mbedtls_sys::ecjpake_self_test(1)==0);
	}
}
