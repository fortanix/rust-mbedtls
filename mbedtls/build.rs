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

extern crate gcc;

use std::env;

fn main() {
	let mut sources=vec!["src/rust_printf.c"];
	if env::var_os("CARGO_FEATURE_STD").is_none() {
		sources.extend(&["src/no_std/strstr.c","src/no_std/snprintf.c","src/no_std/string.c"]);
	}
	gcc::compile_library("librust-mbedtls.a",&sources);
	// Force correct link order for mbedtls_printf
	println!("cargo:rustc-link-lib=static=mbedtls");
	println!("cargo:rustc-link-lib=static=mbedx509");
	println!("cargo:rustc-link-lib=static=mbedcrypto");
}
