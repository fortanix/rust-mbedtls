/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

impl super::BuildConfig {
    pub fn cmake(&self) {
        static INSTALL_DIR: &str = "lib";

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
        // Ensure same installation directory is used on all platforms
        .define("LIB_INSTALL_DIR", INSTALL_DIR)
        // We're building a static library, not an executable, so the try_compile stage of the
        // cmake build should try to compile a static library as well.
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
        .build_target("install");
        for cflag in &self.cflags {
            cmk.cflag(cflag);
        }
        let cc = cc::Build::new().get_compiler();
        if cc.is_like_clang() && cc.args().iter().any(|arg| arg == "-mllvm") {
            cmk.define("CMAKE_C_COMPILER_FORCED", "TRUE");
        }

        let target = std::env::var("TARGET").expect("TARGET environment variable should be set in build scripts");
        // thumbv6m-none-eabi, thumbv7em-none-eabi, thumbv7em-none-eabihf,
        // thumbv7m-none-eabi probably use arm-none-eabi-gcc which can cause the
        // cmake compiler test to fail.
        if target.starts_with("thumbv") && target.contains("none-eabi") {
            // When building on Linux, -rdynamic flag is added automatically. Changing the
            // CMAKE_SYSTEM_NAME to Generic avoids this.
            cmk.define("CMAKE_SYSTEM_NAME", "Generic");
        }

        let mut dst = cmk.build();

        dst.push(INSTALL_DIR);
        println!(
            "cargo:rustc-link-search=native={}",
            dst.to_str().expect("link-search UTF-8 error")
        );

        println!("cargo:rustc-link-lib=mbedtls");
        println!("cargo:rustc-link-lib=mbedx509");
        println!("cargo:rustc-link-lib=mbedcrypto");

        println!(
            "cargo:include={}",
            ::std::env::current_dir()
                .unwrap()
                .join(&self.mbedtls_include)
                .to_str()
                .expect("include/ UTF-8 error")
        );
        println!("cargo:config_h={}", self.config_h.to_str().expect("config.h UTF-8 error"));
    }
}
