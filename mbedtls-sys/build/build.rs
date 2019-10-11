/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */




#[cfg(feature = "build")]
extern crate bindgen;
#[cfg(feature = "build")]
extern crate cmake;

#[cfg(feature = "build")]
mod config;
#[cfg(feature = "build")]
mod headers;
#[cfg(feature = "build")]
#[path = "bindgen.rs"]
mod mod_bindgen;
#[cfg(feature = "build")]
#[path = "cmake.rs"]
mod mod_cmake;

#[cfg(feature = "build")]
pub mod real_build {
    use std::collections::HashMap;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use crate::{mod_bindgen, mod_cmake, headers, config, cmake, bindgen};

    pub fn have_feature(feature: &'static str) -> bool {
        env::var_os(
            format!("CARGO_FEATURE_{}", feature)
                .to_uppercase()
                .replace("-", "_"),
        )
        .is_some()
    }

    pub struct BuildConfig {
        pub out_dir: PathBuf,
        pub mbedtls_src: PathBuf,
        pub config_h: PathBuf,
    }

    impl BuildConfig {
        fn create_config_h(&self) {
            let target = env::var("TARGET").unwrap();
            let mut defines = config::DEFAULT_DEFINES
                .iter()
                .cloned()
                .collect::<HashMap<_, _>>();
            for &(feat, def) in config::FEATURE_DEFINES {
                if (feat == "std") && (target == "x86_64-fortanix-unknown-sgx") {
                    continue;
                }
                if have_feature(feat) {
                    defines.insert(def.0, def.1);
                }
            }

            File::create(&self.config_h)
                .and_then(|mut f| {
                    f.write_all(config::PREFIX.as_bytes())?;
                    for (name, def) in defines {
                        f.write_all(def.define(name).as_bytes())?;
                    }
                    if have_feature("custom_printf") {
                        writeln!(f, "int mbedtls_printf(const char *format, ...);")?;
                    }
                    if have_feature("custom_threading") {
                        writeln!(f, "typedef void* mbedtls_threading_mutex_t;")?;
                    }
                    f.write_all(config::SUFFIX.as_bytes())
                })
                .expect("config.h I/O error");
        }

        fn print_rerun_files(&self) {
            println!("cargo:rerun-if-env-changed=RUST_MBEDTLS_SYS_SOURCE");
            println!(
                "cargo:rerun-if-changed={}",
                self.mbedtls_src.join("CMakeLists.txt").display()
            );
            let include = self.mbedtls_src.join(Path::new("include").join("mbedtls"));
            for h in headers::enabled_ordered() {
                println!("cargo:rerun-if-changed={}", include.join(h).display());
            }
            for f in self
                .mbedtls_src
                .join("library")
                .read_dir()
                .expect("read_dir failed")
            {
                println!(
                    "cargo:rerun-if-changed={}",
                    f.expect("DirEntry failed").path().display()
                );
            }
        }
    }

    pub fn main() {
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR environment not set?"));
        let src = PathBuf::from(env::var("RUST_MBEDTLS_SYS_SOURCE").unwrap_or("vendor".to_owned()));
        let cfg = BuildConfig {
            config_h: out_dir.join("config.h"),
            out_dir: out_dir,
            mbedtls_src: src,
        };

        cfg.create_config_h();
        cfg.print_rerun_files();
        cfg.cmake();
        cfg.bindgen();
    }
}

#[cfg(feature = "build")]
fn main() {
    real_build::main();
}

#[cfg(not(feature = "build"))]
fn main() {
    let target = std::env::var_os("TARGET").unwrap();
    let host = std::env::var_os("HOST").unwrap();
    
    if cfg!(test) || (cfg!(not(feature = "cross-compile")) && target == host) || (cfg!(feature = "cross-compile") && target != host) {
        let cargo = std::env::var_os("CARGO").unwrap();
        let args = [
            /* cargo, */ "run",
            "--bin", "build-script-build",
            "--features", "build",
            "--target-dir", /* $OUT_DIR/bindgen */
        ];
        let mut target_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        target_dir.push("bindgen");
        assert!(std::process::Command::new(&cargo).args(args.iter()).arg(&target_dir).status().unwrap().success())
    }
}