/// Returns the Cargo build-unit identifier from either supported build directory layout.
///
/// Cargo controls this layout independently of rustc's version, so inspect the path instead of
/// relying on the active toolchain version. The legacy layout is
/// `build/mbedtls-<hash>/out`; the new layout is `build/mbedtls/<hash>/out`.
///
/// Ref:
/// - https://github.com/rust-lang/cargo/issues/15010
/// - https://github.com/rust-lang/cargo/issues/17182
pub(crate) fn compilation_symbol_suffix(out_dir: &str) -> Option<&str> {
    let mut components = out_dir.rsplit(|c| c == '/' || c == '\\');
    if components.next()? != "out" {
        return None;
    }

    let build_unit = components.next()?;
    if let Some(suffix) = build_unit.strip_prefix("mbedtls-") {
        return (!suffix.is_empty()).then_some(suffix);
    }

    if !build_unit.is_empty() && components.next()? == "mbedtls" {
        return Some(build_unit);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::compilation_symbol_suffix;

    #[test]
    fn extracts_suffix_from_supported_cargo_layouts() {
        let test_cases = [
            // Legacy Cargo layout on Unix.
            ("target/debug/build/mbedtls-3202cb041a903437/out", "3202cb041a903437"),
            // Cargo build directory layout v2 on Unix.
            ("target/debug/build/mbedtls/f8d961f56b5f3f44/out", "f8d961f56b5f3f44"),
            // Legacy Cargo layout on Windows.
            (r"target\debug\build\mbedtls-3202cb041a903437\out", "3202cb041a903437"),
            // Cargo build directory layout v2 on Windows.
            (r"target\debug\build\mbedtls\f8d961f56b5f3f44\out", "f8d961f56b5f3f44"),
        ];

        for (out_dir, suffix) in test_cases {
            assert_eq!(compilation_symbol_suffix(out_dir), Some(suffix));
        }
    }

    #[test]
    fn rejects_unsupported_or_malformed_cargo_layouts() {
        let test_cases = [
            "target/debug/build/mbedtls/hash/not-out",
            "target/debug/build/other-crate-3202cb041a903437/out",
            "target/debug/build/other-crate/f8d961f56b5f3f44/out",
            "target/debug/build/mbedtls/out",
            "target/debug/build/mbedtls-/out",
            "target/debug/build/mbedtls//out",
        ];

        for out_dir in test_cases {
            assert_eq!(compilation_symbol_suffix(out_dir), None);
        }
    }
}
