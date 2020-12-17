/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate cc;

use std::env;

fn main() {
    let mut b = cc::Build::new();
    b.include(env::var_os("DEP_MBEDTLS_INCLUDE").expect("Links was not properly set in mbedtls-sys package, missing DEP_MBEDTLS_INCLUDE"));
    let config_file = format!("\"{}\"", env::var_os("DEP_MBEDTLS_CONFIG_H").expect("Links was not properly set in mbedtls-sys package, missing DEP_MBEDTLS_CONFIG_H").to_str().unwrap());
    b.define("MBEDTLS_CONFIG_FILE",
             Some(config_file.as_str()));
    
    b.file("src/mbedtls_malloc.c");
    b.file("src/rust_printf.c");
    if env::var_os("CARGO_FEATURE_STD").is_none()
        || ::std::env::var("TARGET")
	    .map(|s| (s == "x86_64-unknown-none-gnu") || (s == "x86_64-fortanix-unknown-sgx"))
	    == Ok(true)
    {
        b.flag("-U_FORTIFY_SOURCE")
            .define("_FORTIFY_SOURCE", Some("0"))
            .flag("-ffreestanding");
    }
    b.compile("librust-mbedtls.a");
    // Force correct link order for mbedtls_printf
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
}
