/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use rustc_version::Channel;
use std::env;

/// Retrieves or generates a metadata value used for symbol name mangling to ensure unique C symbols.
/// When building with Cargo, the metadata value is extracted from the OUT_DIR environment variable.
/// For Bazel builds, this method generate the suffix by hashing part of the crate OUT_DIR,
/// which are sufficient for ensuring symbol uniqueness.
fn get_compilation_symbol_suffix() -> String {
    let out_dir: std::path::PathBuf = std::env::var_os("OUT_DIR").unwrap().into();
    let mut out_dir_it_rev = out_dir.iter().rev();
    if out_dir_it_rev.next().map_or(false, |p| p == "out") {
        // If Cargo is used as build system.
        let crate_ = out_dir_it_rev.next().unwrap().to_string_lossy();
        assert!(crate_.starts_with("mbedtls-"), "Expected directory to start with 'mbedtls-'");
        return crate_[8..].to_owned(); // Return the part after "mbedtls-"
    } else if out_dir.iter().rfind(|p| p.to_string_lossy() == "bazel-out").is_some() {
        let mut hasher = DefaultHasher::new();
        // Reverse the iterator and hash until you find "bazel-out"
        for p in out_dir.iter().rev().take_while(|p| p.to_string_lossy() != "bazel-out") {
            p.hash(&mut hasher);
        }
        
        let hash = hasher.finish();
        return format!("{:016x}", hash);
    }
     else {
        panic!("unexpected OUT_DIR format: {}", out_dir.to_string_lossy());
    }
}

fn main() {
    // used for configuring rustdoc attrs for now
    if rustc_version::version_meta().is_ok_and(|v| v.channel == Channel::Nightly) {
        println!("cargo:rustc-cfg=nightly");
    }
    let symbol_suffix = get_compilation_symbol_suffix();
    println!("cargo:rustc-env=RUST_MBEDTLS_SYMBOL_SUFFIX={}", symbol_suffix);
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    let env_components = env::var("DEP_MBEDTLS_PLATFORM_COMPONENTS").unwrap();
    let mut sys_platform_components = HashMap::<_, HashSet<_>>::new();
    for mut kv in env_components.split(",").map(|component| component.splitn(2, "=")) {
        let k = kv.next().unwrap();
        let v = kv.next().unwrap();
        sys_platform_components.entry(k).or_insert_with(Default::default).insert(v);
        println!(r#"cargo:rustc-cfg=sys_{}="{}""#, k, v);
    }

    let mut b = cc::Build::new();
    b.include(env::var_os("DEP_MBEDTLS_INCLUDE").unwrap());
    let config_file = format!(r#""{}""#, env::var("DEP_MBEDTLS_CONFIG_H").unwrap());
    b.define("MBEDTLS_CONFIG_FILE", Some(config_file.as_str()));
    b.define("RUST_MBEDTLS_SYMBOL_SUFFIX", Some(symbol_suffix.as_str()));

    b.file("src/mbedtls_malloc.c");
    if sys_platform_components
        .get("c_compiler")
        .map_or(false, |comps| comps.contains("freestanding"))
    {
        b.flag("-U_FORTIFY_SOURCE")
            .define("_FORTIFY_SOURCE", Some("0"))
            .flag("-ffreestanding");
    }
    b.compile("librust-mbedtls.a");
}
