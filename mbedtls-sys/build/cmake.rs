/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use cmake;

use crate::have_feature;

impl super::BuildConfig {
    pub fn cmake(&self) {
        let mut cmk = cmake::Config::new(&self.mbedtls_src);
        cmk.cflag(format!(
            r#"-DMBEDTLS_CONFIG_FILE="<{}>""#,
            self.config_h.to_str().expect("config.h UTF-8 error")
        ))
        .define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        .build_target("lib");

        if ::std::env::var("TARGET").map(|s| s == "i686-linux-android") == Ok(true) {
            cmk.define("TOOLCHAIN_PREFIX", "i686-linux-android")
                .target("i686-linux-android26");
        }
        if ::std::env::var("TARGET").map(|s| s == "armv7-linux-androideabi") == Ok(true) {
            cmk.define("TOOLCHAIN_PREFIX", "arm-linux-androideabi")
                .target("armv7a-linux-androideabi26");
        }
        if ::std::env::var("TARGET").map(|s| s == "aarch64-linux-android") == Ok(true) {
            cmk.define("TOOLCHAIN_PREFIX", "aarch64-linux-android")
                .target("aarch64-linux-android26");
        }

        let target_vendor = ::std::env::var("CARGO_CFG_TARGET_VENDOR")
            .expect("CARGO_CFG_TARGET_VENDOR is set by cargo.");

        // Workaround for Cmake not setting `-m<platform>-version-min` flags properly for asm files
        // See https://gitlab.kitware.com/cmake/cmake/issues/19794
        match ::std::env::var("TARGET").unwrap_or("".to_owned()).as_str() {
            "aarch64-apple-ios" | "armv7-apple-ios" | "armv7s-apple-ios" => {
                cmk.cflag("-miphoneos-version-min=7.0");
            }
            "i386-apple-ios" | "x86_64-apple-ios" => {
                cmk.cflag("-mios-simulator-version-min=7.0");
            }
            _ => {}
        };

        if !have_feature("std")
            || ::std::env::var("TARGET")
                .map(|s| (s == "x86_64-unknown-none-gnu") || (s == "x86_64-fortanix-unknown-sgx"))
                == Ok(true)
        {
            if target_vendor != "apple" {
                println!("cargo:rustc-link-lib=gcc");
            }
            // println!("cargo:rustc-link-lib=gcc");

            cmk.cflag("-fno-builtin")
                .cflag("-D_FORTIFY_SOURCE=0")
                .cflag("-fno-stack-protector");
        }
        let mut dst = cmk.build();
        dst.push("build");
        dst.push("library");
        println!(
            "cargo:rustc-link-search=native={}",
            dst.to_str().expect("link-search UTF-8 error")
        );

        let mut dst = cmk.build();
        dst.push("build");
        dst.push("crypto");
        dst.push("library");
        println!(
            "cargo:rustc-link-search=native={}",
            dst.to_str().expect("link-search UTF-8 error")
        );

        println!("cargo:rustc-link-lib=mbedtls");
        println!("cargo:rustc-link-lib=mbedx509");
        println!("cargo:rustc-link-lib=mbedcrypto");
    }
}
