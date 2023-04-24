/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[allow(non_upper_case_globals)]
pub use mbedtls_platform_support::threading::mbedtls_mutex_free;
#[allow(non_upper_case_globals)]
pub use mbedtls_platform_support::threading::mbedtls_mutex_init;
#[allow(non_upper_case_globals)]
pub use mbedtls_platform_support::threading::mbedtls_mutex_lock;
#[allow(non_upper_case_globals)]
pub use mbedtls_platform_support::threading::mbedtls_mutex_unlock;

#[cfg(test)]
mod tests {

    #[test]
    fn double_free() {
        mbedtls_platform_support::threading::test_double_free()
    }
}
