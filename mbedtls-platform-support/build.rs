/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::collections::{HashMap, HashSet};
use std::env;

fn main() {
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
    b.define("MBEDTLS_CONFIG_FILE",
             Some(config_file.as_str()));

    b.file("src/rust_printf.c");
    if sys_platform_components.get("c_compiler").map_or(false, |comps| comps.contains("freestanding")) {
        b.flag("-U_FORTIFY_SOURCE")
            .define("_FORTIFY_SOURCE", Some("0"))
            .flag("-ffreestanding");
    }
    b.compile("librust-mbedtls-platform-support.a");
    // Force correct link order for mbedtls_printf
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
}
