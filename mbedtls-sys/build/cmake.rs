/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use cmake;

impl super::BuildConfig {
    pub fn cmake(&self) {
        let mut cmk = cmake::Config::new(&self.mbedtls_src);
        cmk.cflag(format!(
            r#"-DMBEDTLS_CONFIG_FILE="\"{}\"""#,
            self.config_h.to_str().expect("config.h UTF-8 error")
        ))
        .define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        .build_target("lib");
        for cflag in &self.cflags {
            cmk.cflag(cflag);
        }
        let cc = cc::Build::new().get_compiler();
        if cc.is_like_clang() && cc.args().iter().any(|arg| arg == "-mllvm") {
            cmk.define("CMAKE_C_COMPILER_FORCED", "TRUE");
        }

        let mut dst = cmk.build();

        dst.push("build");
        dst.push("library");
        println!(
            "cargo:rustc-link-search=native={}",
            dst.to_str().expect("link-search UTF-8 error")
        );

        assert!(dst.pop());
        dst.push("crypto");
        dst.push("library");
        println!(
            "cargo:rustc-link-search=native={}",
            dst.to_str().expect("link-search UTF-8 error")
        );

        println!("cargo:rustc-link-lib=mbedtls");
        println!("cargo:rustc-link-lib=mbedx509");
        println!("cargo:rustc-link-lib=mbedcrypto");

        println!("cargo:include={}", ::std::env::current_dir().unwrap().join(&self.mbedtls_include).to_str().expect("include/ UTF-8 error"));
        println!("cargo:config_h={}", self.config_h.to_str().expect("config.h UTF-8 error"));
    }
}
