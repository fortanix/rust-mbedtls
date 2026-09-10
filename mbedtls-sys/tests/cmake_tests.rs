#![allow(dead_code, unused_imports)]
include!("../build/build.rs");

use mod_cmake::*;

macro_rules! unit_test {
    ($fn_name:ident, $target:literal, $cc_is_like_clang:expr, $result:expr) => {
        #[test]
        fn $fn_name() {
            // set the testing environment up
            let cfg = BuildConfig::new();
            cfg.create_config_h();
            cfg.print_rerun_files();
            let mut cmk = cmake::Config::new(&cfg.mbedtls_src);

            assert_eq!(
                mitigate_cve_2022_66442($cc_is_like_clang, &$target.to_string(), &mut cmk),
                $result
            );
        }
    };
}

unit_test!(x86_plus_non_clang, "x86_64-unknown-linux-gnu", false, false);
unit_test!(x86_plus_clang, "x86_64-unknown-linux-gnu", true, false);
unit_test!(arm_plus_non_clang, "aarch64-unknown-linux-musl", false, false);
unit_test!(arm_plus_clang, "aarch64-unknown-linux-musl", true, false);
unit_test!(riscv_plus_non_clang, "riscv64gc-unknown-linux-gnu", false, false);
unit_test!(riscv_plus_clang, "riscv64gc-unknown-linux-gnu", true, true);
