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
        let target = std::env::var("TARGET").expect("TARGET environment variable should be set in build scripts");
        mitigate_cve_2022_66442(cc.is_like_clang(), &target, &mut cmk);
        if cc.is_like_clang() && cc.args().iter().any(|arg| arg == "-mllvm") {
            cmk.define("CMAKE_C_COMPILER_FORCED", "TRUE");
        }

        println!("cargo:rerun-if-env-changed=RUST_MBED_C_COMPILER_BAREMETAL");
        let c_compiler_baremetal = std::env::var("RUST_MBED_C_COMPILER_BAREMETAL")
            .map(|val| val == "1")
            .unwrap_or_default();

        // thumbv6m-none-eabi, thumbv7em-none-eabi, thumbv7em-none-eabihf,
        // thumbv7m-none-eabi probably use arm-none-eabi-gcc which can cause the
        // cmake compiler test to fail.
        if target.starts_with("thumbv") && target.contains("none-eabi") || c_compiler_baremetal {
            // When building on Linux, -rdynamic flag is added automatically. Changing the
            // CMAKE_SYSTEM_NAME to Generic avoids this.
            cmk.define("CMAKE_SYSTEM_NAME", "Generic");
        }
        if target.contains("windows") {
            // Start from rust stable 1.87.0 (2025-05-15)
            // Windows: The standard library no longer links advapi32, except on win7.
            // Ref: https://github.com/rust-lang/rust/pull/138233
            println!("cargo:rustc-link-lib=advapi32");
        }

        let dst = cmk.build();

        println!(
            "cargo:rustc-link-search=native={}",
            dst.join(INSTALL_DIR).to_str().expect("link-search UTF-8 error")
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

use super::config;

/// To mitigate CVE-2025-66442, make sure select-optimize is disabled when necessary
/// returns true iff "-mllvm" and "--disable-select-optimize=true" flags are added to cmk
/// Note: this function is public only because we have a unit test for it in test/cmake_tests.rs
/// Note: this function returns a boolean so that we can confirm its functionality via a unit test
pub fn mitigate_cve_2022_66442(cc_is_like_clang: bool, target: &String, cmk: &mut cmake::Config) -> bool {
    let target_asm_protected =
        target.contains("x86_64") || target.contains("i686") || target.starts_with("arm") || target.starts_with("aarch64");
    let mbedtls_have_asm = config::default_defines().get("MBEDTLS_HAVE_ASM") == Some(&config::Macro::Defined);

    if cc_is_like_clang && !(target_asm_protected && mbedtls_have_asm) {
        cmk.cflag("-mllvm --disable-select-optimize=true");
        return true;
    }
    return false;
}
