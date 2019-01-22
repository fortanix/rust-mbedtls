/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use mbedtls::bignum::Mpi;

#[cfg(feature = "std")]
#[test]
fn bignum_from_str() {
    use std::str::FromStr;

    let p256_16 =
        Mpi::from_str("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
            .unwrap();
    let p256_10 = Mpi::from_str(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    )
    .unwrap();

    assert!(p256_16.eq(&p256_10));

    assert_eq!(
        format!("{}", p256_10),
        "115792089210356248762697446949407573530086143415290314195533631308867097853951"
    );
    assert_eq!(
        format!("{:X}", p256_10),
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
    );
    assert_eq!(
        format!("{:o}", p256_10),
        "17777777777400000000010000000000000000000000000000000077777777777777777777777777777777"
    );
    assert_eq!(format!("{:b}", p256_10), "1111111111111111111111111111111100000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
}

#[test]
fn bignum() {
    let six = Mpi::new(6).unwrap();

    assert_eq!(six.byte_length().unwrap(), 1);
    assert_eq!(six.bit_length().unwrap(), 3);

    let six_bytes = six.to_binary().unwrap();
    assert_eq!(six_bytes.len(), 1);
    assert_eq!(six_bytes[0], 6);

    let five = Mpi::new(5).unwrap();
    assert_eq!(six.cmp(&five), ::std::cmp::Ordering::Greater);
    assert_eq!(five.cmp(&five), ::std::cmp::Ordering::Equal);
    assert_eq!(five.cmp(&six), ::std::cmp::Ordering::Less);

    let bigger = Mpi::new(0x2a2f5dce).unwrap();

    assert_eq!(bigger.byte_length().unwrap(), 4);
    assert_eq!(bigger.bit_length().unwrap(), 30);

    let b_bytes = bigger.to_binary().unwrap();
    assert_eq!(b_bytes.len(), 4);
    assert_eq!(b_bytes[0], 0x2a);
    assert_eq!(b_bytes[1], 0x2f);
    assert_eq!(b_bytes[2], 0x5d);
    assert_eq!(b_bytes[3], 0xce);

    assert!(bigger.eq(&Mpi::from_binary(&b_bytes).unwrap()));
}

#[test]
fn bignum_shifts() {
    let x = Mpi::new(3).unwrap();

    let y = (&x << 30).unwrap();

    assert_eq!(format!("{}", y), "3221225472");

    let y = (&y >> 30).unwrap();

    assert_eq!(format!("{}", y), "3");

    let y = (&y >> 2).unwrap();

    assert_eq!(format!("{}", y), "0");

    let mut z = Mpi::new(1).unwrap();

    z <<= 5;
    assert_eq!(format!("{}", z), "32");
    z <<= 15;
    assert_eq!(format!("{}", z), "1048576");

    z >>= 10;
    assert_eq!(format!("{}", z), "1024");
}

#[test]
fn bignum_op_assign() {
    let mut x = Mpi::new(4).unwrap();

    x += 9;

    assert_eq!(format!("{}", x), "13");

    x += Mpi::new(13).unwrap();

    assert_eq!(format!("{}", x), "26");

    let y = Mpi::new(10).unwrap();
    x += &y;

    assert_eq!(format!("{}", x), "36");

    x -= 3;
    assert_eq!(format!("{}", x), "33");

    x -= Mpi::new(5).unwrap();
    assert_eq!(format!("{}", x), "28");

    x -= &y;
    assert_eq!(format!("{}", x), "18");

    x *= &y;
    assert_eq!(format!("{}", x), "180");

    x *= 2;
    assert_eq!(format!("{}", x), "360");

    x *= Mpi::new(-2).unwrap();
    assert_eq!(format!("{}", x), "-720");

    x /= Mpi::new(-3).unwrap();
    assert_eq!(format!("{}", x), "240");

    x /= 2;
    assert_eq!(format!("{}", x), "120");

    x /= &y;
    assert_eq!(format!("{}", x), "12");

    x %= 100;
    assert_eq!(format!("{}", x), "12");

    x %= Mpi::new(5).unwrap();
    assert_eq!(format!("{}", x), "2");

    assert_eq!(format!("{}", y), "10"); // verify y not moved
}

#[test]
fn bignum_cmp() {
    let big = Mpi::new(2147483647).unwrap();
    let small = Mpi::new(2).unwrap();

    assert!(big > small);
    assert!(small < big);
    assert!(big >= small);
    assert!(small <= big);
    assert!(small >= small);
    assert!(big <= big);
    assert!(small == small);
    assert!(small != big);
}

#[test]
fn bigint_ops() {
    let x = Mpi::new(100).unwrap();
    let y = Mpi::new(20900).unwrap();

    assert_eq!(x.as_u32().unwrap(), 100);

    let z = (&x + &y).unwrap();
    assert_eq!(z.as_u32().unwrap(), 21000);

    let z = (&z * &y).unwrap();
    assert_eq!(z, Mpi::new(438900000).unwrap());

    let z = (&z - &x).unwrap();
    assert_eq!(z, Mpi::new(0x1A2914BC).unwrap());

    let r = (&z % 127).unwrap();
    assert_eq!(r.as_u32().unwrap(), 92);

    let r = (&z % &Mpi::new(127).unwrap()).unwrap();
    assert_eq!(r.as_u32().unwrap(), 92);

    let q = (&z / 53).unwrap();
    assert_eq!(q.as_u32().unwrap(), 8281130);

    let q = (&z / &Mpi::new(53).unwrap()).unwrap();
    assert_eq!(q.as_u32().unwrap(), 8281130);

    let nan = &z / 0;
    assert!(nan.is_err());
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bits: &[u8]) -> mbedtls::Result<String> {
    let zero = Mpi::new(0)?;
    let mut n = Mpi::from_binary(bits)?;
    let radix: i64 = 58;

    let mut s = Vec::new();

    while n > zero {
        let (q, r) = n.divrem_int(radix)?;
        n = q;
        s.push(BASE58_ALPHABET[r.as_u32()? as usize]);
    }

    s.reverse();
    Ok(String::from_utf8(s).unwrap())
}

fn base58_decode(b58: &str) -> mbedtls::Result<Vec<u8>> {
    let radix: i64 = 58;

    let mut n = Mpi::new(0)?;

    fn base58_val(b: u8) -> mbedtls::Result<usize> {
        for (i, c) in BASE58_ALPHABET.iter().enumerate() {
            if *c == b {
                return Ok(i);
            }
        }
        Err(mbedtls::Error::Base64InvalidCharacter)
    }

    for c in b58.bytes() {
        let v = base58_val(c)? as i64;
        n = (&n * radix)?;
        n = (&n + v)?;
    }

    n.to_binary()
}

#[test]
fn test_base58_encode() {
    fn test_base58_rt(input: &[u8], expected: &str) {
        assert_eq!(base58_encode(input).unwrap(), expected);
        assert_eq!(base58_decode(expected).unwrap(), input);
    }

    test_base58_rt(b"", "");
    test_base58_rt(&[32], "Z");
    test_base58_rt(&[45], "n");
    test_base58_rt(&[48], "q");
    test_base58_rt(&[49], "r");
    test_base58_rt(&[57], "z");
    test_base58_rt(&[45, 49], "4SU");
    test_base58_rt(&[49, 49], "4k8");
    test_base58_rt(b"abc", "ZiCa");
    test_base58_rt(b"1234598760", "3mJr7AoUXx2Wqd");
    test_base58_rt(
        b"abcdefghijklmnopqrstuvwxyz",
        "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
    );
}
