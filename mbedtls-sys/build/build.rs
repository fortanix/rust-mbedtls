/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate bindgen;
extern crate cmake;

mod config;
mod headers;
#[path = "bindgen.rs"]
mod mod_bindgen;
#[path = "cmake.rs"]
mod mod_cmake;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn have_feature(feature: &'static str) -> bool {
    env::var_os(
        format!("CARGO_FEATURE_{}", feature)
            .to_uppercase()
            .replace("-", "_"),
    )
    .is_some()
}

struct BuildConfig {
    out_dir: PathBuf,
    mbedtls_src: PathBuf,
    config_h: PathBuf,
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
                if have_feature("custom_time") {
                    writeln!(f, "typedef int64_t time_t;")?;
                    writeln!(f, "time_t mbedtls_time(time_t *);")?;
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

fn main() {
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
