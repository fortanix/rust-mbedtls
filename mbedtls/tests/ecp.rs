extern crate mbedtls;

use mbedtls::ecp::{EcGroup, EcPoint};
use mbedtls::pk::EcGroupId;
use mbedtls::bignum::Mpi;

#[test]
fn test_ec_group() {

    let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();

    assert_eq!(secp256r1.group_id().unwrap(), EcGroupId::SecP256R1);

    let p = secp256r1.p().unwrap().to_binary().unwrap();

    let p256 = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    assert_eq!(p, p256);

    assert_eq!(secp256r1.cofactor().unwrap(), 1);
}

#[test]
#[cfg(feature = "std")]
fn test_ecp_encode() {
    use std::str::FromStr;

    let mut secp256k1 = EcGroup::new(EcGroupId::SecP256K1).unwrap();
    let bitlen = secp256k1.p().unwrap().bit_length().unwrap();
    let g = secp256k1.generator().unwrap();
    assert_eq!(g.is_zero().unwrap(), false);

    let k = Mpi::new(0xC3FF2).unwrap();
    let pt = g.mul(&mut secp256k1, &k).unwrap();

    let pt_uncompressed = pt.to_binary(&secp256k1, false).unwrap();
    assert_eq!(pt_uncompressed.len(), 1 + 2*(bitlen/8));
    let rec_pt = EcPoint::from_binary(&secp256k1, &pt_uncompressed).unwrap();
    assert_eq!(pt.eq(&rec_pt).unwrap(), true);

    let pt_compressed = pt.to_binary(&secp256k1, true).unwrap();
    assert_eq!(pt_compressed.len(), 1 + bitlen/8);

    /*
    Mbedtls supports encoding a point to compressed, but does not
    support reading it back, so skip trying to do that.
    */

    let affine_x = pt.x().unwrap();
    assert_eq!(affine_x, Mpi::from_str("0x1E248FB0AB87942E4B74446F7C9CD151468919B525C108759876F806CA2FFC87").unwrap());
    let affine_y = pt.y().unwrap();
    assert_eq!(affine_y, Mpi::from_str("0x821F40015051C2E37E85A97D96B83A9948FB108E06C98F5AD2CF275C8A9B004B").unwrap());
    let pt_from_components = EcPoint::from_components(&affine_x, &affine_y).unwrap();
    assert!(pt.eq(&pt_from_components).unwrap());
}

#[test]
fn test_ecp_mul() {

    let mut secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();

    let g = secp256r1.generator().unwrap();
    assert_eq!(g.is_zero().unwrap(), false);

    let k = Mpi::new(380689).unwrap();
    let half_k = Mpi::new(617).unwrap();

    /*
    Basic sanity check - multiplying twice by k is same as multiply by k**2
    */
    let pt1 = g.mul(&mut secp256r1, &k).unwrap();
    assert_eq!(pt1.is_zero().unwrap(), false);

    let pt2 = g.mul(&mut secp256r1, &half_k).unwrap();
    assert_eq!(pt2.is_zero().unwrap(), false);
    assert_eq!(pt1.eq(&pt2).unwrap(), false);

    let pt3 = pt2.mul(&mut secp256r1, &half_k).unwrap();
    assert_eq!(pt1.eq(&pt3).unwrap(), true);
    assert_eq!(pt3.eq(&pt1).unwrap(), true);

    assert_eq!(secp256r1.contains_point(&pt3).unwrap(), true);
    let secp256k1 = EcGroup::new(EcGroupId::SecP256K1).unwrap();
    assert_eq!(secp256k1.contains_point(&pt3).unwrap(), false);
}

#[test]
fn test_ecp_mul_add() {

    let mut secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();

    let g = secp256r1.generator().unwrap();

    let k1 = Mpi::new(1212238156).unwrap();
    let k2 = Mpi::new(1163020627).unwrap();

    // Test that k1*g + k2*g == k2*g + k1*g
    let pt1 = EcPoint::muladd(&mut secp256r1, &g, &k2, &g, &k1).unwrap();
    let pt2 = EcPoint::muladd(&mut secp256r1, &g, &k1, &g, &k2).unwrap();
    assert_eq!(pt1.eq(&pt2).unwrap(), true);

    // Todo a better test ...
}
