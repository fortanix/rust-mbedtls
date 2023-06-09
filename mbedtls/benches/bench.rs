/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[macro_use]
extern crate bencher;

use bencher::{black_box, Bencher};

const PBKDF2_NUM_ITERATIONS: u32 = 100000;
const PBKDF2_SALT_LEN: usize = 32;
const PBKDF2_KEY_LEN: usize = 32;

use mbedtls::hash;

fn bench_pbkdf2_hmac(b: &mut Bencher) {
    let password = "password".as_bytes();
    let salt = vec![123u8; PBKDF2_SALT_LEN];

    let mut key_val: Vec<u8> = vec![0; PBKDF2_KEY_LEN];

    b.iter(|| {
        // Inner closure, the actual test
        black_box(
            hash::pbkdf2_hmac(
                hash::Type::Sha512,
                password,
                &salt,
                PBKDF2_NUM_ITERATIONS,
                key_val.as_mut_slice(),
            )
            .unwrap(),
        );
    });
}

benchmark_group!(benches, bench_pbkdf2_hmac);
benchmark_main!(benches);
