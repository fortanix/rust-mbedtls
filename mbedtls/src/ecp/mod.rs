/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::error::{codes, Error, IntoResult, Result};
use core::convert::TryFrom;
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use crate::bignum::Mpi;
use crate::pk::EcGroupId;

define!(
    #[c_ty(ecp_group)]
    struct EcGroup;
    const init: fn() -> Self = ecp_group_init;
    const drop: fn(&mut Self) = ecp_group_free;
    impl<'a> Into<ptr> {}
);

impl Clone for EcGroup {
    fn clone(&self) -> Self {
        fn copy_group(group: &EcGroup) -> Result<EcGroup> {
            /*
            ecp_group_copy only works for named groups, for custom groups we
            must perform the copy manually.
            */
            if group.group_id()? != EcGroupId::None {
                let mut ret = EcGroup::init();
                unsafe { ecp_group_copy(ret.handle_mut(), group.handle()) }.into_result()?;
                Ok(ret)
            } else {
                let generator = group.generator()?;
                EcGroup::from_parameters(
                    group.p()?,
                    group.a()?,
                    group.b()?,
                    generator.x()?,
                    generator.y()?,
                    group.order()?,
                )
            }
        }

        copy_group(self).expect("EcGroup::copy success")
    }
}

impl PartialEq for EcGroup {
    fn eq(&self, other: &EcGroup) -> bool {
        self.p() == other.p()
            && self.a() == other.a()
            && self.b() == other.b()
            && self.order() == other.order()
            && self.generator() == other.generator()
    }
}

impl Eq for EcGroup {}

impl TryFrom<EcGroupId> for EcGroup {
    type Error = Error;

    fn try_from(id: EcGroupId) -> Result<EcGroup> {
        EcGroup::new(id)
    }
}

impl EcGroup {
    pub fn new(group: EcGroupId) -> Result<EcGroup> {
        let mut ret = Self::init();
        unsafe { ecp_group_load(&mut ret.inner, group.into()) }.into_result()?;
        Ok(ret)
    }

    /// Initialize an EcGroup with custom group parameters.
    ///
    /// HAZMAT: This function DOES NOT perform a full check on parameters
    /// against all known attacks. The caller MUST make sure that parameters are
    /// trusted. Failing to comply with this requirement may result in the use
    /// of INSECURE curves. Prefer [EcGroup::new] with known curves listed in
    /// [EcGroupId].
    pub fn from_parameters(p: Mpi, a: Mpi, b: Mpi, g_x: Mpi, g_y: Mpi, order: Mpi) -> Result<EcGroup> {
        let mut ret = Self::init();

        ret.inner.pbits = p.bit_length()?;
        ret.inner.nbits = order.bit_length()?;
        ret.inner.h = 0; // indicate to mbedtls that the values are not static constants

        let zero = Mpi::new(0)?;

        // basic bounds checking
        if &a < &zero
            || &a >= &p
            || &b < &zero
            || &b >= &p
            || &g_x < &zero
            || &g_x >= &p
            || &g_y < &zero
            || &g_y >= &p
            || &order <= &zero
            || (&a == &zero && &b == &zero)
        {
            return Err(codes::EcpBadInputData.into());
        }

        // Compute `order - 2`, needed below.
        let two = Mpi::new(2)?;
        let order_m2 = (&order - &two)?;

        unsafe {
            ret.inner.P = p.into_inner();
            ret.inner.A = a.into_inner();
            ret.inner.B = b.into_inner();
            ret.inner.N = order.into_inner();
            ret.inner.G.X = g_x.into_inner();
            ret.inner.G.Y = g_y.into_inner();
            mpi_lset(&mut ret.inner.G.Z, 1);
        }

        /*
        Test that the provided generator satisfies the curve equation
         */
        if unsafe { ecp_check_pubkey(&ret.inner, &ret.inner.G) } != 0 {
            return Err(codes::EcpBadInputData.into());
        }

        /*
        Test that generator has the expected order, ie that order*G == infinity

        We cannot use ecp_mul for this because ecp_mul requires that the scalar
        be less than the order. So instead split the scalar into order-2 and 2
        and test that G*(order-2) + G*2 == infinity.
         */
        let mut g_m = EcPoint::init(); // will be G*order

        unsafe {
            ecp_muladd(
                &mut ret.inner,
                &mut g_m.inner,
                two.handle(),
                &ret.inner.G,
                order_m2.handle(),
                &ret.inner.G,
            )
        }
        .into_result()?;

        let is_zero = unsafe { ecp_is_zero(&g_m.inner as *const ecp_point as *mut ecp_point) };

        if is_zero != 1 {
            return Err(codes::EcpBadInputData.into());
        }

        Ok(ret)
    }

    pub fn group_id(&self) -> Result<EcGroupId> {
        Ok(EcGroupId::from(self.inner.id))
    }

    pub fn p(&self) -> Result<Mpi> {
        Mpi::copy(&self.inner.P)
    }

    pub fn a(&self) -> Result<Mpi> {
        // Mbedtls uses A == NULL to indicate -3 mod p
        if self.inner.A.p == ::core::ptr::null_mut() {
            let mut neg3 = self.p()?;
            neg3 -= 3;
            Ok(neg3)
        } else {
            Mpi::copy(&self.inner.A)
        }
    }

    pub fn b(&self) -> Result<Mpi> {
        Mpi::copy(&self.inner.B)
    }

    pub fn order(&self) -> Result<Mpi> {
        Mpi::copy(&self.inner.N)
    }

    pub fn cofactor(&self) -> Result<u32> {
        match self.group_id()? {
            EcGroupId::Curve25519 => Ok(8),
            EcGroupId::Curve448 => Ok(4),
            // Requires a point-counting algorithm such as SEA.
            EcGroupId::None => Err(codes::EcpFeatureUnavailable.into()),
            _ => Ok(1),
        }
    }

    pub fn generator(&self) -> Result<EcPoint> {
        EcPoint::copy(&self.inner.G)
    }

    pub fn contains_point(&self, point: &EcPoint) -> Result<bool> {
        match unsafe { ecp_check_pubkey(&self.inner, &point.inner) } {
            0 => Ok(true),
            ERR_ECP_INVALID_KEY => Ok(false),
            err => Err(err.into()),
        }
    }
}

define!(
    #[c_ty(ecp_point)]
    struct EcPoint;
    const init: fn() -> Self = ecp_point_init;
    const drop: fn(&mut Self) = ecp_point_free;
    impl<'a> Into<ptr> {}
);

impl Clone for EcPoint {
    fn clone(&self) -> Self {
        let mut ret = Self::init();
        unsafe { ecp_copy(&mut ret.inner, &self.inner) }
            .into_result()
            .expect("ecp_copy success");
        ret
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &EcPoint) -> bool {
        self.eq(other).unwrap()
    }
}

impl EcPoint {
    pub fn new() -> Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_set_zero(&mut ret.inner) }.into_result()?;
        Ok(ret)
    }

    pub(crate) fn copy(other: &ecp_point) -> Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_copy(&mut ret.inner, other) }.into_result()?;
        Ok(ret)
    }

    pub fn from_binary(group: &EcGroup, bin: &[u8]) -> Result<EcPoint> {
        let prefix = *bin.get(0).ok_or(Error::from(codes::EcpBadInputData))?;

        if prefix == 0x02 || prefix == 0x03 {
            // Compressed point, which mbedtls does not understand
            let y_mod_2 = if prefix == 0x03 { true } else { false };

            let p = group.p()?;
            let a = group.a()?;
            let b = group.b()?;

            if bin.len() != (p.byte_length()? + 1) {
                return Err(codes::EcpBadInputData.into());
            }

            let x = Mpi::from_binary(&bin[1..]).unwrap();

            // Now compute y = sqrt(x^3 + ax + b)
            let three = Mpi::new(3)?;
            let ax = (&x * &a)?.modulo(&p)?;
            let x3 = x.mod_exp(&three, &p)?;
            let x3_ax_b = (&(&x3 + &ax)? + &b)?.modulo(&p)?;
            let mut y = x3_ax_b.mod_sqrt(&p)?;

            if y.get_bit(0) != y_mod_2 {
                y = (&p - &y)?;
            }
            EcPoint::from_components(x, y)
        } else {
            let mut ret = Self::init();
            unsafe { ecp_point_read_binary(&group.inner, &mut ret.inner, bin.as_ptr(), bin.len()) }.into_result()?;
            Ok(ret)
        }
    }

    pub fn from_binary_no_compress(group: &EcGroup, bin: &[u8]) -> Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_point_read_binary(&group.inner, &mut ret.inner, bin.as_ptr(), bin.len()) }.into_result()?;
        Ok(ret)
    }

    pub fn from_components(x: Mpi, y: Mpi) -> Result<EcPoint> {
        let mut ret = Self::init();

        unsafe {
            ret.inner.X = x.into_inner();
            ret.inner.Y = y.into_inner();
            mpi_lset(&mut ret.inner.Z, 1).into_result()?;
        };

        Ok(ret)
    }

    pub fn x(&self) -> Result<Mpi> {
        Mpi::copy(&self.inner.X)
    }

    pub fn y(&self) -> Result<Mpi> {
        Mpi::copy(&self.inner.Y)
    }

    pub fn is_zero(&self) -> Result<bool> {
        /*
        mbedtls_ecp_is_zero takes arg as non-const for no particular reason
        use this unsafe cast here to avoid having to take &mut self
         */
        match unsafe { ecp_is_zero(&self.inner as *const ecp_point as *mut ecp_point) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(codes::EcpInvalidKey.into()),
        }
    }

    /// This function performs a scalar multiplication of a point by an integer: R = m *  P.
    ///
    /// This function does not accept a RNG so there is no blinding applied.
    #[deprecated(
        since = "0.12.3",
        note = "This function does not accept an RNG so it's vulnerable to side channel attacks.
Please use `mul_with_rng` instead."
    )]
    pub fn mul(&self, group: &mut EcGroup, k: &Mpi) -> Result<EcPoint> {
        // Note: mbedtls_ecp_mul performs point validation itself so we skip that here

        let mut ret = Self::init();

        unsafe {
            ecp_mul(
                &mut group.inner,
                &mut ret.inner,
                k.handle(),
                &self.inner,
                None,
                ::core::ptr::null_mut(),
            )
        }
        .into_result()?;

        Ok(ret)
    }

    /// This function performs a scalar multiplication of a point by an integer: `R = k * self`.
    ///
    /// It uses the group's base field operations to prevent timing attacks, executing the same sequence regardless of `k`.
    /// Some intermediate results are randomized using the provided RNG function for blinding.
    ///
    ///
    /// # Arguments
    ///
    /// * `group` - The elliptic curve group to use.
    /// * `k` - The integer scalar by which to multiply.
    /// * `rng` - The RNG used for blinding (randomizing some intermediate results) to defend side channel attacks.
    ///
    /// # Returns
    ///
    /// * `Result<EcPoint>` - The resulting point after multiplication on success.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * The scalar `k` is not valid as a private key, determined by mbedtls function [`mbedtls_ecp_check_privkey`].
    /// * The point `self` is not valid as a public key, determined by mbedtls function [`mbedtls_ecp_check_pubkey`].
    /// * Memory allocation fails.
    /// * Any other kind of failure occurs during the execution of the underlying [`mbedtls_ecp_mul`] function.
    ///
    /// [`mbedtls_ecp_check_pubkey`]: https://github.com/fortanix/rust-mbedtls/blob/main/mbedtls-sys/vendor/include/mbedtls/ecp.h#L1115-L1143
    /// [`mbedtls_ecp_check_privkey`]: https://github.com/fortanix/rust-mbedtls/blob/main/mbedtls-sys/vendor/include/mbedtls/ecp.h#L1145-L1165
    /// [`mbedtls_ecp_mul`]: https://github.com/fortanix/rust-mbedtls/blob/main/mbedtls-sys/vendor/include/mbedtls/ecp.h#L933-L971
    pub fn mul_with_rng<F: crate::rng::Random>(&self, group: &mut EcGroup, k: &Mpi, rng: &mut F) -> Result<EcPoint> {
        // Note: mbedtls_ecp_mul performs point validation itself so we skip that here

        let mut ret = Self::init();

        unsafe {
            ecp_mul(
                &mut group.inner,
                &mut ret.inner,
                k.handle(),
                &self.inner,
                Some(F::call),
                rng.data_ptr(),
            )
        }
        .into_result()?;

        Ok(ret)
    }

    /// Compute pt1*k1 + pt2*k2 -- not const time
    pub fn muladd(group: &mut EcGroup, pt1: &EcPoint, k1: &Mpi, pt2: &EcPoint, k2: &Mpi) -> Result<EcPoint> {
        let mut ret = Self::init();

        if group.contains_point(&pt1)? == false {
            return Err(codes::EcpInvalidKey.into());
        }

        if group.contains_point(&pt2)? == false {
            return Err(codes::EcpInvalidKey.into());
        }

        unsafe {
            ecp_muladd(
                &mut group.inner,
                &mut ret.inner,
                k1.handle(),
                &pt1.inner,
                k2.handle(),
                &pt2.inner,
            )
        }
        .into_result()?;

        Ok(ret)
    }

    pub fn eq(&self, other: &EcPoint) -> Result<bool> {
        let r = unsafe { ecp_point_cmp(&self.inner, &other.inner) };

        match r {
            0 => Ok(true),
            ERR_ECP_BAD_INPUT_DATA => Ok(false),
            x => Err(x.into()),
        }
    }

    /// This function checks equalness of two points in const time.
    ///
    /// The implementation is based on C mbedtls function [`mbedtls_ecp_point_cmp`].
    /// This new implementation ensures there is no shortcut when any of `x, y ,z` fields of two points is not equal.
    ///
    /// [`mbedtls_ecp_point_cmp`]: https://github.com/fortanix/rust-mbedtls/blob/main/mbedtls-sys/vendor/library/ecp.c#L809-L825
    pub fn eq_const_time(&self, other: &EcPoint) -> Result<bool> {
        let x = crate::bignum::mpi_inner_eq_const_time(&self.inner.X, &other.inner.X);
        let y = crate::bignum::mpi_inner_eq_const_time(&self.inner.Y, &other.inner.Y);
        let z = crate::bignum::mpi_inner_eq_const_time(&self.inner.Z, &other.inner.Z);
        match (x, y, z) {
            (Ok(true), Ok(true), Ok(true)) => Ok(true),
            (Ok(_), Ok(_), Ok(_)) => Ok(false),
            (Ok(_), Ok(_), Err(e)) => Err(e),
            (Ok(_), Err(e), _) => Err(e),
            (Err(e), _, _) => Err(e),
        }
    }

    pub fn to_binary(&self, group: &EcGroup, compressed: bool) -> Result<Vec<u8>> {
        /*
        We know biggest group supported is P-521 so just allocate a
        vector big enough and then resize it down to the actual output
        length

        ceil(521/8) == 66
        OS2ECP format is header byte + 2 point elements (or 1 if compressed)
        so max size is 66*2+1 = 133
         */
        let mut olen = 0;
        let mut buf = vec![0u8; 133];

        let format = if compressed { ECP_PF_COMPRESSED } else { ECP_PF_UNCOMPRESSED };

        unsafe { ecp_point_write_binary(&group.inner, &self.inner, format, &mut olen, buf.as_mut_ptr(), buf.len()) }
            .into_result()?;

        assert!(olen <= buf.len());

        buf.truncate(olen);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {

    use crate::bignum::Mpi;
    use crate::ecp::{EcGroup, EcPoint};
    use crate::pk::EcGroupId;

    #[test]
    fn test_ec_group() {
        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();

        assert_eq!(secp256r1.group_id().unwrap(), EcGroupId::SecP256R1);

        let p = secp256r1.p().unwrap().to_binary().unwrap();

        let p256 = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert_eq!(p, p256);

        assert_eq!(secp256r1.cofactor().unwrap(), 1);

        let copy = EcGroup::from_parameters(
            secp256r1.p().unwrap(),
            secp256r1.a().unwrap(),
            secp256r1.b().unwrap(),
            secp256r1.generator().unwrap().x().unwrap(),
            secp256r1.generator().unwrap().y().unwrap(),
            secp256r1.order().unwrap(),
        )
        .unwrap();

        assert!(secp256r1 == copy); //can't use assert_eq as EcGroup doesn't
                                    // impl Debug
    }

    // FIXME: very slow on SGX https://github.com/fortanix/rust-mbedtls/issues/134
    #[cfg_attr(target_env = "sgx", ignore)]
    #[test]
    fn test_ec_compressed_points() {
        let groups = [
            EcGroupId::Bp256R1,
            EcGroupId::Bp384R1,
            EcGroupId::Bp512R1,
            EcGroupId::SecP192K1,
            EcGroupId::SecP192R1,
            EcGroupId::SecP224K1,
            EcGroupId::SecP224R1,
            EcGroupId::SecP256K1,
            EcGroupId::SecP256R1,
            EcGroupId::SecP384R1,
            EcGroupId::SecP521R1,
        ];

        let mut k = Mpi::new(0xB00FB00F).unwrap();

        for group_id in &groups {
            let mut group = EcGroup::new(*group_id).unwrap();

            let p_len = group.p().unwrap().byte_length().unwrap();

            let generator = group.generator().unwrap();

            for i in 0..32 {
                k += i;

                let pt = generator
                    .mul_with_rng(&mut group, &k, &mut crate::test_support::rand::test_rng())
                    .unwrap();

                let uncompressed_pt = pt.to_binary(&group, false).unwrap();
                assert_eq!(uncompressed_pt.len(), 1 + p_len * 2);

                let pt_u = EcPoint::from_binary(&group, &uncompressed_pt).unwrap();
                assert_eq!(pt_u.x().unwrap(), pt.x().unwrap());
                assert_eq!(pt_u.y().unwrap(), pt.y().unwrap());

                let compressed_pt = pt.to_binary(&group, true).unwrap();
                assert_eq!(compressed_pt.len(), 1 + p_len);

                let pt_c = EcPoint::from_binary(&group, &compressed_pt).unwrap();
                assert_eq!(pt_c.x().unwrap(), pt.x().unwrap());
                assert_eq!(pt_c.y().unwrap(), pt.y().unwrap());
            }
        }
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
        let pt = g
            .mul_with_rng(&mut secp256k1, &k, &mut crate::test_support::rand::test_rng())
            .unwrap();

        let pt_uncompressed = pt.to_binary(&secp256k1, false).unwrap();
        assert_eq!(pt_uncompressed.len(), 1 + 2 * (bitlen / 8));
        let rec_pt = EcPoint::from_binary(&secp256k1, &pt_uncompressed).unwrap();
        assert_eq!(pt.eq(&rec_pt).unwrap(), true);

        let pt_compressed = pt.to_binary(&secp256k1, true).unwrap();
        assert_eq!(pt_compressed.len(), 1 + bitlen / 8);
        let rec_pt = EcPoint::from_binary(&secp256k1, &pt_compressed).unwrap();
        assert_eq!(pt.eq(&rec_pt).unwrap(), true);

        let affine_x = pt.x().unwrap();
        assert_eq!(
            affine_x,
            Mpi::from_str("0x1E248FB0AB87942E4B74446F7C9CD151468919B525C108759876F806CA2FFC87").unwrap()
        );
        let affine_y = pt.y().unwrap();
        assert_eq!(
            affine_y,
            Mpi::from_str("0x821F40015051C2E37E85A97D96B83A9948FB108E06C98F5AD2CF275C8A9B004B").unwrap()
        );
        let pt_from_components = EcPoint::from_components(affine_x, affine_y).unwrap();
        assert!(pt.eq(&pt_from_components).unwrap());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_custom_curves() {
        use std::str::FromStr;

        // Check that various invalid curves cannot be created

        // this is secp112r1
        let p = Mpi::from_str("0xDB7C2ABF62E35E668076BEAD208B").unwrap();
        let a = Mpi::from_str("0xDB7C2ABF62E35E668076BEAD2088").unwrap();
        let b = Mpi::from_str("0x659EF8BA043916EEDE8911702B22").unwrap();
        let g_x = Mpi::from_str("0x09487239995A5EE76B55F9C2F098").unwrap();
        let g_y = Mpi::from_str("0xA89CE5AF8724C0A23E0E0FF77500").unwrap();
        let order = Mpi::from_str("0xDB7C2ABF62E35E7628DFAC6561C5").unwrap();

        // correct parameters are accepted
        assert!(EcGroup::from_parameters(p.clone(), a.clone(), b.clone(), g_x.clone(), g_y.clone(), order.clone()).is_ok());

        // swap (x,y) in generator
        assert!(EcGroup::from_parameters(p.clone(), a.clone(), b.clone(), g_y.clone(), g_x.clone(), order.clone()).is_err());

        // swap (a,b) in equation
        assert!(EcGroup::from_parameters(p.clone(), b.clone(), a.clone(), g_x.clone(), g_y.clone(), order.clone()).is_err());

        // pass p as the order
        assert!(EcGroup::from_parameters(p.clone(), b.clone(), a.clone(), g_x.clone(), g_y.clone(), p.clone()).is_err());

        // invalid order
        let order_p_3 = (&order + &Mpi::new(3).unwrap()).unwrap();
        assert!(
            EcGroup::from_parameters(p.clone().clone(), b.clone(), a.clone(), g_x.clone(), g_y.clone(), order_p_3).is_err()
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_gost_sign() {
        use std::str::FromStr;

        // Test from RFC 7901
        let p = Mpi::from_str("0x8000000000000000000000000000000000000000000000000000000000000431").unwrap();
        let a = Mpi::from_str("7").unwrap();
        let b = Mpi::from_str("0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E").unwrap();
        let order = Mpi::from_str("0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3").unwrap();
        let g_x = Mpi::from_str("2").unwrap();
        let g_y = Mpi::from_str("0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8").unwrap();

        let mut gost = EcGroup::from_parameters(p.clone(), a, b, g_x, g_y, order.clone()).unwrap();

        let gost_g = gost.generator().unwrap();

        let d = Mpi::from_str("0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28").unwrap();

        let pubkey = gost_g
            .mul_with_rng(&mut gost, &d, &mut crate::test_support::rand::test_rng())
            .unwrap();

        let pubkey_x = pubkey.x().unwrap();
        let pubkey_y = pubkey.y().unwrap();

        let exp_pub_x = Mpi::from_str("0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B").unwrap();
        let exp_pub_y = Mpi::from_str("0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA").unwrap();

        assert_eq!(pubkey_x, exp_pub_x);
        assert_eq!(pubkey_y, exp_pub_y);

        let k = Mpi::from_str("0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3").unwrap();

        let gk = gost_g
            .mul_with_rng(&mut gost, &k, &mut crate::test_support::rand::test_rng())
            .unwrap();

        let exp_gk_x = Mpi::from_str("0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493");
        let exp_gk_y = Mpi::from_str("0x489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E");

        assert_eq!(gk.x(), exp_gk_x);
        assert_eq!(gk.y(), exp_gk_y);

        let hm = Mpi::from_str("0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5").unwrap();

        let mut e = hm.modulo(&order).unwrap();

        if e == Mpi::new(0).unwrap() {
            e = Mpi::new(1).unwrap();
        }

        let r = gk.x().unwrap();

        //s = (r * d + k * e) mod q

        let rd = (&r * &d).unwrap();
        let ke = (&k * &e).unwrap();
        let s = ((&rd + &ke).unwrap()).modulo(&order).unwrap();

        let exp_r = Mpi::from_str("0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493").unwrap();
        let exp_s = Mpi::from_str("0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40").unwrap();

        assert_eq!(r, exp_r);
        assert_eq!(s, exp_s);

        // now verify the signature

        let v = e.modinv(&order).unwrap();

        let z1 = (&s * &v).unwrap().modulo(&order).unwrap();
        let z2 = (&order - &((&r * &v).unwrap().modulo(&order).unwrap())).unwrap();

        let c = EcPoint::muladd(&mut gost, &gost_g, &z1, &pubkey, &z2).unwrap();

        let xr = c.x().unwrap().modulo(&order).unwrap();

        assert_eq!(xr, r);
    }

    #[test]
    fn test_ecp_const_eq() {
        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();
        let g = secp256r1.generator().unwrap();
        let zero = EcPoint::new().unwrap();
        assert!(g.eq(&g).unwrap());
        assert!(zero.eq(&zero).unwrap());
        assert!(!g.eq(&zero).unwrap());
        assert!(g.eq_const_time(&g).unwrap());
        assert!(zero.eq_const_time(&zero).unwrap());
        assert!(!g.eq_const_time(&zero).unwrap());
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
        let pt1 = g
            .mul_with_rng(&mut secp256r1, &k, &mut crate::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(pt1.is_zero().unwrap(), false);

        let pt2 = g
            .mul_with_rng(&mut secp256r1, &half_k, &mut crate::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(pt2.is_zero().unwrap(), false);
        assert_eq!(pt1.eq(&pt2).unwrap(), false);

        let pt3 = pt2
            .mul_with_rng(&mut secp256r1, &half_k, &mut crate::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(pt1.eq(&pt3).unwrap(), true);
        assert_eq!(pt3.eq(&pt1).unwrap(), true);

        assert_eq!(secp256r1.contains_point(&pt3).unwrap(), true);
        let secp256k1 = EcGroup::new(EcGroupId::SecP256K1).unwrap();
        assert_eq!(secp256k1.contains_point(&pt3).unwrap(), false);
    }

    #[test]
    fn test_ecp_mul_add() {
        let mut group1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();
        let mut group2 = group1.clone();

        let g = group1.generator().unwrap();

        let k1 = Mpi::new(1212238156).unwrap();
        let k2 = Mpi::new(1163020627).unwrap();

        // Test that k1*g + k2*g == k2*g + k1*g
        let pt1 = EcPoint::muladd(&mut group1, &g, &k2, &g, &k1).unwrap();
        let pt2 = EcPoint::muladd(&mut group2, &g, &k1, &g, &k2).unwrap();
        assert_eq!(pt1.eq(&pt2).unwrap(), true);

        let pt3 = pt1.clone();
        assert_eq!(pt2.eq(&pt3).unwrap(), true);
    }

    #[cfg(feature = "std")]
    struct Params<'a> {
        p: &'a str,
        a: &'a str,
        b: &'a str,
        g_x: &'a str,
        g_y: &'a str,
        n: &'a str,
    }

    #[cfg(feature = "std")]
    impl Into<super::Result<EcGroup>> for Params<'_> {
        fn into(self) -> super::Result<EcGroup> {
            use std::str::FromStr;
            EcGroup::from_parameters(
                Mpi::from_str(self.p)?,
                Mpi::from_str(self.a)?,
                Mpi::from_str(self.b)?,
                Mpi::from_str(self.g_x)?,
                Mpi::from_str(self.g_y)?,
                Mpi::from_str(self.n)?,
            )
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn pathological_parameters() {
        // y² = x³ mod 7 (note  a == b == 0)
        let singular: super::Result<_> = Params {
            p: "0x07",
            a: "0x00",
            b: "0x00",
            g_x: "0x01",
            g_y: "0x02",
            n: "0x0b",
        }
        .into();
        assert!(singular.is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn bad_generators() {
        // y² = x³ + x + 6 (mod 7) with bad generator (1, 2) and prime order 11
        let small_curve: super::Result<_> = Params {
            p: "0x07",
            a: "0x01",
            b: "0x06",
            g_x: "0x01",
            g_y: "0x02",
            n: "0x0b",
        }
        .into();
        assert!(small_curve.is_err());

        // y² = x³ + x + 6 (mod 7) with bad generator (0, 0) and prime order 11
        let small_curve_zero_gen: super::Result<_> = Params {
            p: "0x07",
            a: "0x01",
            b: "0x06",
            g_x: "0x00",
            g_y: "0x00",
            n: "0x0b",
        }
        .into();
        assert!(small_curve_zero_gen.is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn unknown_cofactor() {
        // y² = x³ + x + 6 (mod 7)  with generator (1, 6) and prime order 11
        let small_curve: super::Result<_> = Params {
            p: "0x07",
            a: "0x01",
            b: "0x06",
            g_x: "0x01",
            g_y: "0x06",
            n: "0x0b",
        }
        .into();
        assert!(small_curve.unwrap().cofactor().is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn zero_params_curves() {
        use super::Result;
        // Barreto-Naehrig 254, note a = 0
        let bn254: Result<_> = Params {
            p: "0x2523648240000001BA344D80000000086121000000000013A700000000000013",
            a: "0x0000000000000000000000000000000000000000000000000000000000000000",
            b: "0x0000000000000000000000000000000000000000000000000000000000000002",
            g_x: "0x2523648240000001BA344D80000000086121000000000013A700000000000012",
            g_y: "0x0000000000000000000000000000000000000000000000000000000000000001",
            n: "0x2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",
        }
        .into();
        assert!(bn254.is_ok());

        // Prescribed embedded degree of 12, BLS12-381
        let bls12_381: Result<_> = Params {
            p: "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
            a: "0x00",
            b: "0x04",
            g_x: "0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB",
            g_y: "0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1",
            n: "0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001",
        }
        .into();
        assert!(bls12_381.is_ok());

        // Fp256BN
        let fp256_bn: Result<_> = Params {
            p: "0xfffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013",
            a: "0x00",
            b: "0x03",
            g_x: "0x01",
            g_y: "0x02",
            n: "0xfffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
        }
        .into();
        assert!(fp256_bn.is_ok());

        // id-GostR3410-2001-CryptoPro-C-ParamSet, note g_x = 0
        let gost_r3410: Result<_> = Params {
            p: "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
            a: "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598",
            b: "0x805a",
            g_x: "0x00",
            g_y: "0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67",
            n: "0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
        }
        .into();
        assert!(gost_r3410.is_ok());

        // secp256k1 (Bitcoin), note a = 0
        let my_secp256k1: Result<EcGroup> = Params {
            p: "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            a: "0x0000000000000000000000000000000000000000000000000000000000000000",
            b: "0x0000000000000000000000000000000000000000000000000000000000000007",
            g_x: "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            g_y: "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            n: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        }
        .into();
        assert!(my_secp256k1.is_ok());
        let my_secp256k1 = my_secp256k1.unwrap();

        // We compare against the known SecP256K1
        let secp256k1 = EcGroup::new(EcGroupId::SecP256K1).unwrap();
        assert!(my_secp256k1.p() == secp256k1.p());
        assert!(my_secp256k1.a() == secp256k1.a());
        assert!(my_secp256k1.b() == secp256k1.b());
        assert!(my_secp256k1.generator() == secp256k1.generator());
        assert!(my_secp256k1.order() == secp256k1.order());
    }
}
