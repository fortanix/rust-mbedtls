/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

impl super::BuildConfig {
    pub fn cmake(&self) {
        let mut cmk = cmake::Config::new(&self.mbedtls_src);
        cmk.cflag(format!(
            r#"-DMBEDTLS_CONFIG_FILE="\"{}\"""#,
            self.config_h.to_str().expect("config.h UTF-8 error")
        ))
        .define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        // This is turn off on windows by default
        .define("GEN_FILES", "ON")
        // Prefer unix-style over Apple-style Python3 on macOS, required for the Github Actions CI
        .define("Python3_FIND_FRAMEWORK", "LAST")
        .build_target("install");
        for cflag in &self.cflags {
            cmk.cflag(cflag);
        }
        let cc = cc::Build::new().get_compiler();
        if cc.is_like_clang() && cc.args().iter().any(|arg| arg == "-mllvm") {
            cmk.define("CMAKE_C_COMPILER_FORCED", "TRUE");
        }

        println!("cargo:rerun-if-env-changed=RUST_MBED_C_COMPILER_BAREMETAL");
        let c_compiler_baremetal = std::env::var("RUST_MBED_C_COMPILER_BAREMETAL")
            .map(|val| val == "1")
            .unwrap_or_default();

        let target = std::env::var("TARGET").expect("TARGET environment variable should be set in build scripts");
        // thumbv6m-none-eabi, thumbv7em-none-eabi, thumbv7em-none-eabihf,
        // thumbv7m-none-eabi probably use arm-none-eabi-gcc which can cause the
        // cmake compiler test to fail.
        if target.starts_with("thumbv") && target.contains("none-eabi") || c_compiler_baremetal {
            // When building on Linux, -rdynamic flag is added automatically. Changing the
            // CMAKE_SYSTEM_NAME to Generic avoids this.
            cmk.define("CMAKE_SYSTEM_NAME", "Generic");
            // The compiler test requires _exit which is not available. By just trying to
            // compile a library, we can fix it.
            cmk.define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY");
        }

        let dst = cmk.build();

        println!(
            "cargo:rustc-link-search=native={}",
            dst.join("lib").to_str().expect("link-search UTF-8 error")
        );

        println!("cargo:rustc-link-lib=static=mbedtls");
        println!("cargo:rustc-link-lib=static=mbedx509");
        println!("cargo:rustc-link-lib=static=mbedcrypto");

        println!(
            "cargo:include={}",
            dst.join("include").to_str().expect("include/ UTF-8 error")
        );
        println!("cargo:config_h={}", self.config_h.to_str().expect("config.h UTF-8 error"));
    }
}
