// Cargo's build directory layout is an implementation detail. Keep this parser separate from
// build.rs so it can be exercised by the crate's ordinary unit tests.

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
        return Some(suffix);
    }

    if components.next()? == "mbedtls" {
        return Some(build_unit);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::compilation_symbol_suffix;

    #[test]
    fn extracts_suffix_from_legacy_cargo_layout() {
        let out_dir = "target/debug/build/mbedtls-3202cb041a903437/out";
        assert_eq!(compilation_symbol_suffix(out_dir), Some("3202cb041a903437"));
    }

    #[test]
    fn extracts_suffix_from_new_cargo_layout() {
        let out_dir = "target/debug/build/mbedtls/f8d961f56b5f3f44/out";
        assert_eq!(compilation_symbol_suffix(out_dir), Some("f8d961f56b5f3f44"));
    }

    #[test]
    fn extracts_suffix_from_legacy_windows_cargo_layout() {
        let out_dir = r"target\debug\build\mbedtls-3202cb041a903437\out";
        assert_eq!(compilation_symbol_suffix(out_dir), Some("3202cb041a903437"));
    }

    #[test]
    fn extracts_suffix_from_new_windows_cargo_layout() {
        let out_dir = r"target\debug\build\mbedtls\f8d961f56b5f3f44\out";
        assert_eq!(compilation_symbol_suffix(out_dir), Some("f8d961f56b5f3f44"));
    }
}
