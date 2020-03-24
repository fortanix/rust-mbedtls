/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use bindgen;
use bindgen::callbacks::{ParseCallbacks, IntKind, EnumVariantValue, DeriveTrait};

use std::fs::File;
use std::io::Write;

use crate::headers;

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, _name: &str, i: i64) -> Option<IntKind> {
        Some(if i >= 0 {
            if i <= (::std::i32::MAX as i64) { IntKind::I32 } else { IntKind::I64 }
        } else {
            if i >= (::std::i32::MIN as i64) { IntKind::I32 } else { IntKind::I64 }
        })
    }

    fn item_name(&self, name: &str) -> Option<String> {
        if (name.starts_with("mbedtls_") || name.starts_with("MBEDTLS_")) && name != "mbedtls_time_t" {
            Some(name[8..].to_owned())
        } else {
            None
        }
    }

    fn enum_variant_name(&self, _enum_name: Option<&str>, variant_name: &str, _variant_value: EnumVariantValue)
                         -> Option<String> {
        if variant_name.starts_with("MBEDTLS_") {
            Some(variant_name[8..].to_owned())
        } else {
            None
        }
    }

    fn can_blacklisted_derive(&self, item_name: &str, derive_trait: DeriveTrait) -> bool {
        match item_name {
            "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" |
            "int8_t" | "int16_t" | "int32_t" | "int64_t" | "size_t" =>
                match derive_trait { DeriveTrait::Copy | DeriveTrait::Debug => true, _ => false },
            "pthread_mutex_t" =>
                match derive_trait { DeriveTrait::Copy => true, _ => false },
            _ => false,
        }
    }
}

impl super::BuildConfig {
    pub fn bindgen(&self) {
        // Mbed TLS headers
        let header_main = self.out_dir.join("bindgen-input-main.h");
        File::create(&header_main)
            .and_then(|mut f| {
                Ok(for h in headers::enabled_ordered_main() {
                    writeln!(f, "#include \"mbedtls/{}\"", h)?;
                })
            }).expect("bindgen-input-main.h I/O error");

        let include_main = self.mbedtls_src.join("include");

        // Mbed TLS' crypto module headers
        let header_crypto = self.out_dir.join("bindgen-input-crypto.h");
        File::create(&header_crypto)
            .and_then(|mut f| {
                Ok(for h in headers::enabled_ordered_crypto() {
                    writeln!(f, "#include \"mbedtls/{}\"", h)?;
                })
            }).expect("bindgen-input-crypto.h I/O error");

        let include_crypto = self.mbedtls_src.join("crypto").join("include");

        let bindings = bindgen::builder()
            .header(header_main.into_os_string().into_string().unwrap())
            .header(header_crypto.into_os_string().into_string().unwrap())
            .clang_arg(format!(
                "-DMBEDTLS_CONFIG_FILE=<{}>",
                self.config_h.to_str().expect("config.h UTF-8 error")
            )).clang_arg(format!(
                "-I{}",
                include_main.to_str().expect("include/ UTF-8 error")
            )).clang_arg(format!(
                "-I{}",
                include_crypto.to_str().expect("crypto/include/ UTF-8 error")
            ))
            .whitelist_recursively(false)
            .whitelist_type("mbedtls_.*")
            .whitelist_function("mbedtls_.*")
            .whitelist_var("mbedtls_.*")
            .whitelist_var("MBEDTLS_.*")
            .use_core()
            .ctypes_prefix("crate::types::raw_types")
            .prepend_enum_name(false)
            .parse_callbacks(Box::new(Callbacks))
            .generate()
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
