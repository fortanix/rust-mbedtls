/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use bindgen;

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use bindgen::Formatter;

use crate::headers;

#[derive(Debug)]
struct MbedtlsParseCallbacks;

impl bindgen::callbacks::ParseCallbacks for MbedtlsParseCallbacks {
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        // clean up generated static function suffix
        let original_item_name = original_item_name.trim_end_matches("__extern");
        // remove reductant prefix for code in mbedtls lib
        Some(if original_item_name.starts_with("mbedtls_") {
            original_item_name.trim_start_matches("mbedtls_").to_string()
        } else if original_item_name.starts_with("MBEDTLS_") {
            original_item_name.trim_start_matches("MBEDTLS_").to_string()
        // remove reductant prefix for code in psa lib
        } else if original_item_name.starts_with("psa_") {
            original_item_name.trim_start_matches("psa_").to_string()
        } else if original_item_name.starts_with("PSA_") {
            original_item_name.trim_start_matches("PSA_").to_string()
        } else {
            original_item_name.to_string()
        })
    }

    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        original_variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue
    ) -> Option<String> {
        self.item_name(original_variant_name)
    }

    fn int_macro(&self, _name: &str, value: i64) -> Option<bindgen::callbacks::IntKind> {
        if value < (i32::MIN as i64) || value > (i32::MAX as i64) {
            Some(bindgen::callbacks::IntKind::LongLong)
        } else {
            Some(bindgen::callbacks::IntKind::Int)
        }
    }

    fn blocklisted_type_implements_trait(&self, _name: &str, derive_trait: bindgen::callbacks::DeriveTrait) -> Option<bindgen::callbacks::ImplementsTrait> {
        if derive_trait == bindgen::callbacks::DeriveTrait::Default {
            Some(bindgen::callbacks::ImplementsTrait::Manually)
        } else {
            Some(bindgen::callbacks::ImplementsTrait::Yes)
        }
    }
}

impl super::BuildConfig {
    pub fn bindgen(&self) {
        let mut header = String::new();
        for h in headers::enabled_ordered() {
            let _ = writeln!(header, "#include <mbedtls/{}>", h);
        }
        // add psa header
        header.push_str("#include <psa/crypto.h>\n");

        let mut cc = cc::Build::new();
        cc.include(&self.mbedtls_include)
        .flag(&format!(
            "-DMBEDTLS_CONFIG_FILE=\"{}\"",
            self.config_h.to_str().expect("config.h UTF-8 error")
        ));

        for cflag in &self.cflags {
            cc.flag(cflag);
        }

        // Determine the sysroot for this compiler so that bindgen
        // uses the correct headers
        let compiler = cc.get_compiler();
        if compiler.is_like_gnu() {
            let output = compiler.to_command().args(&["--print-sysroot"]).output();
            match output {
                Ok(sysroot) if sysroot.status.success() => {
                    let path = std::str::from_utf8(&sysroot.stdout).expect("Malformed sysroot");
                    let trimmed_path = path
                        .strip_suffix("\r\n")
                        .or(path.strip_suffix("\n"))
                        .unwrap_or(&path);
                    cc.flag(&format!("--sysroot={}", trimmed_path));
                }
                _ => {} // skip toolchains without a configured sysroot
            };
        }

        
        // generate static function wrappers without any other rust related parameters to ensure
        // correctness of result C code
        bindgen::builder()
            .clang_args(cc.get_compiler().args().iter().map(|arg| arg.to_str().unwrap()))
            .header_contents("bindgen-input.h", &header)
            .wrap_static_fns(true)
            .wrap_static_fns_path(&self.static_wrappers_c)
            .generate().expect("bindgen error");

        // use headers with static function wrappers to generate bindings
        let static_wrappers_code = fs::read_to_string(&self.static_wrappers_c).expect("read static_wrappers.c I/O error");
        let header = format!("{}\n{}", &header, static_wrappers_code);
        // generate bindings for `mbedtls` code
        let bindings = bindgen_builder(&cc, &header)
            .allowlist_function("^(?i)mbedtls_.*")
            .allowlist_type("^(?i)mbedtls_.*")
            .allowlist_var("^(?i)mbedtls_.*")
            .raw_line("#![allow(dead_code, deref_nullptr, non_snake_case, non_camel_case_types, non_upper_case_globals, invalid_value)]")
            .generate()
            .expect("bindgen mbedtls error")
            .to_string();
        // generate bindings for `psa` code
        let psa_bindings = bindgen_builder(&cc, &header)
            .allowlist_function("^(?i)psa_.*")
            .allowlist_type("^(?i)psa_.*")
            .allowlist_var("^(?i)psa_.*")
            .generate()
            .expect("bindgen psa error")
            .to_string();
        // update static function wrappers code with header for later compilation 
        fs::write(&self.static_wrappers_c, &header).expect("write static_wrappers.c I/O error");

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                f.write_all(bindings.as_bytes())?;
                // put bindings of psa code inside a module
                f.write_all(format!("pub mod psa {{\n{}{}\n}}\n", "use super::*;\n",psa_bindings).as_bytes())?;
                f.write_all(b"use self::psa::*;\n")?;
                f.write_all(b"use crate::types::*;\n")?; // for FILE, time_t, etc.
                Ok(())
            }).expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        fs::write(mod_bindings, b"mod bindings;\n").expect("mod-bindings.rs I/O error");
    }
}

// create a bindgen builder with common parameters
fn bindgen_builder(cc: &cc::Build, header: &String) -> bindgen::Builder {
    bindgen::builder()
        .enable_function_attribute_detection()
        .clang_args(cc.get_compiler().args().iter().map(|arg| arg.to_str().unwrap()))
        .header_contents("bindgen-input.h", header)
        .allowlist_recursively(false)
        .blocklist_type("^mbedtls_time_t$")
        .use_core()
        .ctypes_prefix("::types::raw_types")
        .parse_callbacks(Box::new(MbedtlsParseCallbacks))
        .default_enum_style(bindgen::EnumVariation::Consts)
        .generate_comments(false)
        .derive_copy(true)
        .derive_debug(false) // buggy :(
        .derive_default(true)
        .prepend_enum_name(false)
        .translate_enum_integer_types(true)
        .layout_tests(false)
}

