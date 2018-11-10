/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use bindgen;
use bindgen::callbacks::IntKind;

use std::fs::File;
use std::io::Write;

use headers;

#[derive(Debug)]
struct ParseCallbacks {}

impl bindgen::callbacks::ParseCallbacks for ParseCallbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.starts_with("MBEDTLS_SSL_IS_") ||
            name.starts_with("MBEDTLS_SSL_PRESET_") ||
            name.starts_with("MBEDTLS_SSL_TRANSPORT_") ||
            name.starts_with("MBEDTLS_SSL_VERIFY_") ||
            name.starts_with("MBEDTLS_TLS_RSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_RSA_PSK_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECJPAKE_WITH_") ||
            name.starts_with("MBEDTLS_TLS_DHE_RSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECDH_ECDSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECDHE_ECDSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECDH_RSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECDHE_RSA_WITH_") ||
            name.starts_with("MBEDTLS_TLS_ECDHE_PSK_WITH_") ||
            name.starts_with("MBEDTLS_TLS_PSK_WITH_") ||
            name.starts_with("MBEDTLS_TLS_DHE_PSK_WITH_") ||
            name.starts_with("MBEDTLS_SSL_SESSION_TICKETS_") ||
            name.starts_with("MBEDTLS_CTR_DRBG_PR_") ||
            name.starts_with("MBEDTLS_ENTROPY_SOURCE_") ||
            name.starts_with("MBEDTLS_HMAC_DRBG_PR_") ||
            name.starts_with("MBEDTLS_RSA_PKCS_")
             {
            Some(IntKind::Int)
        } else {
            None
        }
    }
    
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        if original_item_name.starts_with("mbedtls_") {
            if original_item_name == "mbedtls_time_t" {
                None
            } else {
                Some(original_item_name.trim_start_matches("mbedtls_").to_string())
            }
        } else if original_item_name.starts_with("MBEDTLS_") {
            Some(original_item_name.trim_start_matches("MBEDTLS_").to_string())
        } else {
            None
        }
    }

    fn enum_variant_name(
        &self, 
        _enum_name: Option<&str>, 
        original_variant_name: &str, 
        _variant_value: bindgen::callbacks::EnumVariantValue
    ) -> Option<String> {
        if original_variant_name.starts_with("MBEDTLS_") {
            Some(original_variant_name.trim_start_matches("MBEDTLS_").to_string())
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
                    try!(writeln!(f, "#include <mbedtls/{}>", h));
                })
            }).expect("bindgen-input.h I/O error");

        let include = self.mbedtls_src.join("include");

        let bindings = bindgen::builder()
            .clang_arg("-Dmbedtls_t_udbl=mbedtls_t_udbl;") // bindgen can't handle unused uint128
            .clang_arg(format!(
                "-DMBEDTLS_CONFIG_FILE=<{}>",
                self.config_h.to_str().expect("config.h UTF-8 error")
            )).clang_arg(format!(
                "-I{}",
                include.to_str().expect("include/ UTF-8 error")
            )).header(
                header
                    .to_str()
                    .expect("failed to convert header path to string"),
            ).use_core()
            .derive_debug(false) // buggy :(
            .disable_name_namespacing()
            .prepend_enum_name(false)
            .ctypes_prefix("raw_types")
            .parse_callbacks(Box::new(ParseCallbacks{}))
            // max_align_t is causing bindgen generated tests to fail an alignment check and
            // is not needed by the bindings.
            .blacklist_type("max_align_t")
            // Including the comments breaks the generated code because it contains formatting
            // that is interpreted as escaped characters.
            .generate_comments(false)
            .generate()
            .expect("bindgen error");

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                try!(bindings.write(Box::new(&mut f)));
                f.write_all(b"use ::types::*;\n") // for FILE, time_t, etc.
            }).expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        File::create(&mod_bindings)
            .and_then(|mut f| f.write_all(b"mod bindings;\n"))
            .expect("mod-bindings.rs I/O error");
    }
}
