/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or 
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version 
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your 
 * option. This file may not be copied, modified, or distributed except 
 * according to those terms. */

extern crate mbedtls;

use mbedtls::pk::{Pk, ECDSA_MAX_LEN};
use mbedtls::hash::Type::Sha256;
use mbedtls::Error;

mod support;
use support::rand::test_rng;

// This is a test key generated with the pk::generate_ec_secp256r1 test.
const TEST_KEY_PEM: &'static str = "-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQCE4WNND2Lx24xc1Q4LPR/CygNZDEOmZF5tmwCTL5CVN6AKBggqhkjO
PQMBB6FEA0IABKlh7VJ0BOcpyY/EWjQjod5K1zGFvOXLm8EPVv/9uQJ/HL4lZxFH
kK4RGxVhveMLxLkqfyWb/N3PyU1nWdr2ZXU=
-----END EC PRIVATE KEY-----
\0";

#[test]
fn sign_verify() {
	let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

	let data = b"SIGNATURE TEST SIGNATURE TEST SI";
	let mut signature = [0u8; ECDSA_MAX_LEN];

	let len = k.sign(Sha256, data, &mut signature, &mut test_rng()).unwrap();
	k.verify(Sha256, data, &signature[0..len]).unwrap();
}

#[test]
fn verify_failure() {
	let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

	let data = b"SIGNATURE TEST SIGNATURE TEST SI";
	let mut signature = [0u8; ECDSA_MAX_LEN];

	k.sign(Sha256, data, &mut signature, &mut test_rng()).unwrap();
	signature[0] ^= 1u8;
	k.verify(Sha256, data, &signature).err().expect("Verify of corrupted signature should fail");
}

#[test]
fn buffer_too_small() {
	let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

	let data = b"SIGNATURE TEST SIGNATURE TEST SI";
	let mut signature = [0u8; ECDSA_MAX_LEN - 1];

	assert_eq!(k.sign(Sha256, data, &mut signature, &mut test_rng()).err(), Some(Error::PkSigLenMismatch));
}
