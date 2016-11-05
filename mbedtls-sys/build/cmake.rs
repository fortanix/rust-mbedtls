/*
 * Rust bindings for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version. Alternatively, you can redistribute it and/or modify it
 * under the terms of the Apache License, Version 2.0. 
 */

use cmake;

use have_feature;

impl super::BuildConfig {
	pub fn cmake(&self) {
		let mut cmk=cmake::Config::new(&self.mbedtls_src);
		cmk
			.cflag(format!(r#"-DMBEDTLS_CONFIG_FILE="<{}>""#,self.config_h.to_str().expect("config.h UTF-8 error")))
			.define("ENABLE_PROGRAMS","OFF")
			.define("ENABLE_TESTING","OFF");
		if !have_feature("std") {
	        println!("cargo:rustc-link-lib=gcc");
			cmk.cflag("-fno-builtin");
			cmk.cflag("-fno-stack-protector");
			cmk.cflag("-D_FORTIFY_SOURCE=0");
		}
		cmk.build_target("clean").build();
		let mut dst=cmk.build_target("lib").build();
		dst.push("build");
		dst.push("library");
		println!("cargo:rustc-link-search=native={}",dst.to_str().expect("link-search UTF-8 error"));
        println!("cargo:rustc-link-lib=mbedtls");
		println!("cargo:rustc-link-lib=mbedx509");
        println!("cargo:rustc-link-lib=mbedcrypto");
	}
}
