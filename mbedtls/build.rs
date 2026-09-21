/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::env;
use std::hash::{Hash, Hasher};
use std::path::Path;

use rustc_version::Channel;

/// Retrieves or generates a metadata value used for symbol name mangling to
/// ensure unique C symbols.
///
/// When building with Cargo, the metadata value is extracted from the OUT_DIR
/// environment variable.
///
/// Historically Cargo used a layout like: `.../build/mbedtls-<hash>/out`
/// Newer Cargo versions use: `.../build/mbedtls/<hash>/out`
///
/// For Bazel builds, generate the suffix by hashing the portion of OUT_DIR
/// beneath `bazel-out`.
fn get_compilation_symbol_suffix() -> String {
    let out_dir: std::path::PathBuf = env::var_os("OUT_DIR")
        .expect("OUT_DIR is not set")
        .into();

    if out_dir.file_name() == Some(Path::new("out").as_os_str()) {
        let parent = out_dir
            .parent()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .expect("Expected parent of OUT_DIR to be valid UTF-8");

        // Old Cargo layout:.../mbedtls-0123456789abcdef/out
        if let Some(suffix) = parent.strip_prefix("mbedtls-") {
            return suffix.to_owned();
        }

        // Newer Cargo layout: .../mbedtls/0123456789abcdef/out
        if !parent.is_empty() &&
            parent.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'_'
            })
        {
            return parent.to_owned();
        }

        // Future-proof fallback - hash the whole OUT_DIR.
        let mut hasher = DefaultHasher::new();
        out_dir.hash(&mut hasher);

        return format!("{:016x}", hasher.finish());
    }

    // If Bazel is used as build system.
    if out_dir.iter().any(|component| component == "bazel-out") {
        let mut hasher = DefaultHasher::new();
        // Reverse the iterator and hash until we find "bazel-out"
        for p in out_dir.iter().rev().take_while(|p| *p != "bazel-out") {
            p.hash(&mut hasher);
        }
        return format!("{:016x}", hasher.finish());
    }

    panic!("unexpected OUT_DIR format: {}", out_dir.display());
}

fn main() {
    // used for configuring rustdoc attrs for now
    if rustc_version::version_meta().is_ok_and(|v| v.channel == Channel::Nightly) {
        println!("cargo:rustc-cfg=nightly");
    }

    let symbol_suffix = get_compilation_symbol_suffix();
    println!("cargo:rustc-env=RUST_MBEDTLS_SYMBOL_SUFFIX={}", symbol_suffix);
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    let env_components = env::var("DEP_MBEDTLS_PLATFORM_COMPONENTS")
        .expect("DEP_MBEDTLS_PLATFORM_COMPONENTS is not set");

    let mut sys_platform_components = HashMap::<_, HashSet<_>>::new();
    for mut kv in env_components.split(',').map(|component| component.splitn(2, '=')) {
        let key = kv.next().expect("platform component key missing");
        let value = kv.next().expect("platform component value missing");

        sys_platform_components.entry(key).or_default().insert(value);

        println!(r#"cargo:rustc-cfg=sys_{}="{}""#, key, value);
    }

    let mut build = cc::Build::new();

    build.include(env::var_os("DEP_MBEDTLS_INCLUDE")
        .expect("DEP_MBEDTLS_INCLUDE is not set"));

    let config_file = format!(r#""{}""#, env::var("DEP_MBEDTLS_CONFIG_H")
        .expect("DEP_MBEDTLS_CONFIG_H is not set"));

    build.define("MBEDTLS_CONFIG_FILE", Some(config_file.as_str()));
    build.define("RUST_MBEDTLS_SYMBOL_SUFFIX", Some(symbol_suffix.as_str()));

    build.file("src/mbedtls_malloc.c");

    if sys_platform_components
        .get("c_compiler")
        .is_some_and(|components| components.contains("freestanding"))
    {
        build.flag("-U_FORTIFY_SOURCE")
            .define("_FORTIFY_SOURCE", Some("0"))
            .flag("-ffreestanding");
    }

    build.compile("librust-mbedtls.a");
}
