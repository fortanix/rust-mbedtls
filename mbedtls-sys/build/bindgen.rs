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
        // rename prefix for code in mbedtls lib to avoid duplicate naming
        } else if original_item_name.starts_with("psa_") {
            format!("libpsa_{}", original_item_name.trim_start_matches("psa_"))
        } else if original_item_name.starts_with("PSA_") {
            format!("LIBPSA_{}", original_item_name.trim_start_matches("PSA_"))
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

/// Add bindgen 0.19-style union accessor methods. These are deprecated
/// and can be deleted with the next major version bump.
fn generate_deprecated_union_accessors(bindings: &str) -> String {
    #[derive(Default)]
    struct UnionImplBuilder {
        impls: String
    }

    impl<'ast> syn::visit::Visit<'ast> for UnionImplBuilder {
        fn visit_item_union(&mut self, i: &'ast syn::ItemUnion) {
            let union_name = &i.ident;
            let field_name = i.fields.named.iter().map(|field| field.ident.as_ref().unwrap());
            let field_type = i.fields.named.iter().map(|field| &field.ty);
            write!(self.impls, "{}", quote::quote! {
                impl #union_name {
                    #(
                        #[deprecated]
                        pub unsafe fn #field_name(&mut self) -> *mut #field_type {
                            &mut self.#field_name
                        }
                    )*
                }
            }).unwrap();
        }
    }

    let mut impl_builder = UnionImplBuilder::default();
    syn::visit::visit_file(&mut impl_builder, &syn::parse_file(&bindings).unwrap());

    impl_builder.impls
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
        let bindings = bindgen::builder()
            .enable_function_attribute_detection()
            .clang_args(cc.get_compiler().args().iter().map(|arg| arg.to_str().unwrap()))
            .header_contents("bindgen-input.h", &header)
            .allowlist_function("^(?i)mbedtls_.*")
            .allowlist_type("^(?i)mbedtls_.*")
            .allowlist_var("^(?i)mbedtls_.*")
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
            .raw_line("#![allow(dead_code, deref_nullptr, non_snake_case, non_camel_case_types, non_upper_case_globals, invalid_value)]")
            .generate()
            .expect("bindgen error")
            .to_string();
        // update static function wrappers code with header for later compilation 
        fs::write(&self.static_wrappers_c, &header).expect("write static_wrappers.c I/O error");

        let union_impls = generate_deprecated_union_accessors(&bindings);

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                f.write_all(bindings.as_bytes())?;
                f.write_all(union_impls.as_bytes())?;
                f.write_all(b"use crate::types::*;\n")?; // for FILE, time_t, etc.
                Ok(())
            }).expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        fs::write(mod_bindings, b"mod bindings;\n").expect("mod-bindings.rs I/O error");
    }
}

