/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

mod crate_id;

use std::collections::{HashMap, HashSet};
use std::env;

use rustc_version::Channel;

/// Return the crate hash that Cargo will be passing to `rustc -C metadata=`.
// If there's a panic in this code block, that means Cargo's way of running the
// build script has changed, and this code should be updated to handle the new
// case.
// Since Bazel does not use Cargo to generate Crate Metadata hash we need to implement a separate one for it.
fn get_compilation_metadata_hash() -> String {
    let out_dir: std::path::PathBuf = std::env::var_os("OUT_DIR").unwrap().into();
    let mut out_dir_it = out_dir.iter().rev();
    let next = out_dir_it.next().unwrap();

    if next == "out" {
        let crate_ = out_dir_it.next().unwrap().to_string_lossy();
        assert!(crate_.starts_with("mbedtls-"));
        return crate_[8..].to_owned();
    } else if next == "_bs.out_dir" {
        let compiler_version = rustc_version::version().expect("Failed to get rustc version").to_string();
        let version = env!("CARGO_PKG_VERSION");
        let versioned_string = format!("mbedtls_{}", version);
        let metadata = vec!["".to_string()];
        let stable_crate_id = crate_id::StableCrateId::new(&versioned_string, false, metadata, compiler_version);

        return stable_crate_id.to_string();
    } else {
        panic!("Unexpected directory structure: {:?}", next);
    }
}

fn main() {
    // used for configuring rustdoc attrs for now
    if rustc_version::version_meta().is_ok_and(|v| v.channel == Channel::Nightly) {
        println!("cargo:rustc-cfg=nightly");
    }

    let metadata_hash = get_compilation_metadata_hash();
    println!("cargo:rustc-env=RUST_MBEDTLS_METADATA_HASH={}", metadata_hash);

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
    b.define("RUST_MBEDTLS_METADATA_HASH", Some(metadata_hash.as_str()));

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
