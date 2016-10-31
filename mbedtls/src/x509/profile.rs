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

use mbedtls_sys::*;

define!(#[repr(C)] struct Profile(x509_crt_profile) {
	impl<'a> Into<*>;
});


extern {
	#[link_name = "mbedtls_x509_crt_profile_default"]
	pub static DEFAULT: Profile;
	#[link_name = "mbedtls_x509_crt_profile_next"]
	pub static NEXT: Profile;
	#[link_name = "mbedtls_x509_crt_profile_suiteb"]
	pub static SUITE_B: Profile;
}
