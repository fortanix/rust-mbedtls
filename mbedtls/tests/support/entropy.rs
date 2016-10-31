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

#[cfg(all(feature="std",not(feature="rdrand")))]
pub fn entropy_new<'a>() -> ::mbedtls::rng::OsEntropy<'a> {
	::mbedtls::rng::OsEntropy::new()
}

#[cfg(feature="rdrand")]
pub fn entropy_new() -> ::mbedtls::rng::Rdseed {
	::mbedtls::rng::Rdseed
}

#[cfg(all(not(feature="std"),not(feature="rdrand")))]
pub fn entropy_new() -> _UNABLE_TO_RUN_TEST_WITHOUT_ENTROPY_SOURCE_ {
	panic!("Unable to run test without entropy source")
}
