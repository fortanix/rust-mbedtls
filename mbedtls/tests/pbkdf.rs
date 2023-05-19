/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls::hash::Type as MdType;
use mbedtls::hash::pbkdf2_hmac;

#[test]
fn test_pbkdf2() {
    let mut output = [0u8; 48];

    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    let iterations = 10000;
    let passphrase = b"xyz";

    pbkdf2_hmac(MdType::Sha256, passphrase, &salt, iterations, &mut output).unwrap();

    assert_eq!(output[0..4], [0xDE, 0xFD, 0x29, 0x87]);

    assert_eq!(output[44..48], [0xE7, 0x0B, 0x72, 0xD0]);
}
