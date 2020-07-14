/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use bindgen;

use std::fs::File;
use std::io::{stderr, Write};

use crate::headers;

#[derive(Debug)]
struct StderrLogger;

impl bindgen::Logger for StderrLogger {
    fn error(&self, msg: &str) {
        let _ = writeln!(stderr(), "Bindgen ERROR: {}", msg);
    }
    fn warn(&self, msg: &str) {
        let _ = writeln!(stderr(), "Bindgen WARNING: {}", msg);
    }
}

impl super::BuildConfig {
    pub fn bindgen(&self) {
        let header = self.out_dir.join("bindgen-input.h");
        File::create(&header)
            .and_then(|mut f| {
                Ok(for h in headers::enabled_ordered() {
                    writeln!(f, "#include <mbedtls/{}>", h)?;
                })
            }).expect("bindgen-input.h I/O error");

        let include = self.mbedtls_src.join("include");

        let logger = StderrLogger;
        let mut bindgen = bindgen::Builder::new(header.into_os_string().into_string().unwrap());
        let bindings = bindgen
            .log(&logger)
            .clang_arg("-Dmbedtls_t_udbl=mbedtls_t_udbl;") // bindgen can't handle unused uint128
            .clang_arg(format!(
                "-DMBEDTLS_CONFIG_FILE=\"{}\"",
                self.config_h.to_str().expect("config.h UTF-8 error")
            )).clang_arg(format!(
                "-I{}",
                include.to_str().expect("include/ UTF-8 error")
            )).match_pat(include.to_str().expect("include/ UTF-8 error"))
            .match_pat(self.config_h.to_str().expect("config.h UTF-8 error"))
            .use_core(true)
            .derive_debug(false) // buggy :(
            .ctypes_prefix(vec!["types".to_owned(), "raw_types".to_owned()])
            .remove_prefix("mbedtls_")
            .rust_enums(false)
            .convert_macros(true)
            .macro_int_types(
                vec![
                    "sint",
                    "sint",
                    "sint",
                    "slonglong",
                    "sint",
                    "sint",
                    "sint",
                    "slonglong",
                ].into_iter(),
            ).generate()
            .expect("bindgen error");

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                bindings.write(Box::new(&mut f))?;
                f.write_all(b"use crate::types::*;\n") // for FILE, time_t, etc.
            }).expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        File::create(&mod_bindings)
            .and_then(|mut f| f.write_all(b"mod bindings;\n"))
            .expect("mod-bindings.rs I/O error");
    }
}
