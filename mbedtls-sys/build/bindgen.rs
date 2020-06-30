/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::fs::File;
use std::io::Write;

use bindgen;
use bindgen::callbacks::IntKind;

use crate::headers;

#[derive(Debug)]
struct ParseCallback;

impl bindgen::callbacks::ParseCallbacks for ParseCallback {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.starts_with("MBEDTLS_") {
            Some(IntKind::Int)
        } else {
            None
        }
    }
    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        original_variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue,
    ) -> Option<String> {
        if original_variant_name.starts_with("MBEDTLS_") {
            Some(
                original_variant_name
                    .trim_start_matches("MBEDTLS_")
                    .to_string(),
            )
        } else {
            None
        }
    }

    fn item_name(&self, original_item_name: &str) -> Option<String> {
       if original_item_name.eq("mbedtls_time_t") {
            None
        } else if original_item_name.starts_with("mbedtls_") {
            Some(
                original_item_name
                    .trim_start_matches("mbedtls_")
                    .to_string(),
            )
        } else if original_item_name.starts_with("MBEDTLS_") {
            Some(
                original_item_name
                    .trim_start_matches("MBEDTLS_")
                    .to_string(),
            )
        } else {
            None
        }
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
            })
            .expect("bindgen-input.h I/O error");

        let include = self.mbedtls_src.join("include");

        let bindings = bindgen::Builder::default()
            .header(header.into_os_string().into_string().unwrap())
            .clang_arg(format!(
                "-DMBEDTLS_CONFIG_FILE=\"{}\"",
                self.config_h.to_str().expect("config.h UTF-8 error")
            ))
            .clang_arg(format!(
                "-I{}",
                include.to_str().expect("include/ UTF-8 error")
            ))
            .use_core()
            .derive_debug(false) // buggy :(
            .parse_callbacks(Box::new(ParseCallback))
            .ctypes_prefix("crate::types::raw_types")
            .blacklist_function("strtold")
            .blacklist_function("qecvt_r")
            .blacklist_function("qecvt")
            .blacklist_function("qfcvt_r")
            .blacklist_function("qgcvt")
            .blacklist_function("qfcvt")
            .opaque_type("std::*")
            .opaque_type("time_t")
            .generate_comments(false)
            .prepend_enum_name(false)
            .size_t_is_usize(true)
            .generate()
            .expect("bindgen error");

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                f.write_all(br#"
                #![allow(nonstandard_style)]
                #![allow(unused_imports)]
                "#)?;

                bindings.write(Box::new(&mut f))?;

                f.write_all(br#"
                // for FILE, time_t, etc.
                use crate::types::*;
                "#)

            })
            .expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        File::create(&mod_bindings)
            .and_then(|mut f| f.write_all(b"mod bindings;\n"))
            .expect("mod-bindings.rs I/O error");
    }
}
