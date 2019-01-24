/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use error::IntoResult;
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use alloc_prelude::*;

use bignum::Mpi;
use pk::EcGroupId;

define!(
    #[c_ty(ecp_group)]
    struct EcGroup;
    const init: fn() -> Self = ecp_group_init;
    const drop: fn(&mut Self) = ecp_group_free;
    impl<'a> Into<ptr> {}
);

impl EcGroup {
    pub fn new(group: EcGroupId) -> ::Result<EcGroup> {
        let mut ret = Self::init();
        unsafe { ecp_group_load(&mut ret.inner, group as u32) }.into_result()?;
        Ok(ret)
    }

    pub fn group_id(&self) -> ::Result<EcGroupId> {
        Ok(EcGroupId::from(self.inner.id))
    }

    pub fn p(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.P)
    }

    pub fn a(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.A)
    }

    pub fn b(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.B)
    }

    pub fn order(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.N)
    }

    pub fn cofactor(&self) -> ::Result<u32> {
        Ok(self.inner.h)
    }

    pub fn generator(&self) -> ::Result<EcPoint> {
        EcPoint::copy(&self.inner.G)
    }

    pub fn contains_point(&self, point: &EcPoint) -> ::Result<bool> {
        match unsafe { ecp_check_pubkey(&self.inner, &point.inner) } {
            0 => Ok(true),
            ERR_ECP_INVALID_KEY => Ok(false),
            err => Err(::Error::from_mbedtls_code(err)),
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

impl EcPoint {
    pub fn new() -> ::Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_set_zero(&mut ret.inner) }.into_result()?;
        Ok(ret)
    }

    pub(crate) fn copy(other: &ecp_point) -> ::Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_copy(&mut ret.inner, other) }.into_result()?;
        Ok(ret)
    }

    pub fn from_binary(group: &EcGroup, bin: &[u8]) -> ::Result<EcPoint> {
        let mut ret = Self::init();
        unsafe { ecp_point_read_binary(&group.inner, &mut ret.inner, bin.as_ptr(), bin.len()) }
            .into_result()?;
        Ok(ret)
    }

    pub fn from_components(x: &Mpi, y: &Mpi) -> ::Result<EcPoint> {
        let mut ret = Self::init();

        unsafe {
            mpi_copy(&mut ret.inner.X, x.handle()).into_result()?;
            mpi_copy(&mut ret.inner.Y, y.handle()).into_result()?;
            mpi_lset(&mut ret.inner.Z, 1).into_result()?;
        };

        Ok(ret)
    }

    pub fn x(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.X)
    }

    pub fn y(&self) -> ::Result<Mpi> {
        Mpi::copy(&self.inner.Y)
    }

    pub fn is_zero(&self) -> ::Result<bool> {
        /*
        mbedtls_ecp_is_zero takes arg as non-const for no particular reason
        use this unsafe cast here to avoid having to take &mut self
        */
        match unsafe { ecp_is_zero(&self.inner as *const ecp_point as *mut ecp_point) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(::Error::EcpInvalidKey),
        }
    }

    pub fn mul(&self, group: &mut EcGroup, k: &Mpi) -> ::Result<EcPoint> {
        // TODO provide random number generator for blinding
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

    /// Compute pt1*k1 + pt2*k2 -- not const time
    pub fn muladd(
        group: &mut EcGroup,
        pt1: &EcPoint,
        k1: &Mpi,
        pt2: &EcPoint,
        k2: &Mpi,
    ) -> ::Result<EcPoint> {
        let mut ret = Self::init();

        if group.contains_point(&pt1)? == false {
            return Err(::Error::EcpInvalidKey);
        }

        if group.contains_point(&pt2)? == false {
            return Err(::Error::EcpInvalidKey);
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

    pub fn eq(&self, other: &EcPoint) -> ::Result<bool> {
        let r = unsafe { ecp_point_cmp(&self.inner, &other.inner) };

        match r {
            0 => Ok(true),
            ERR_ECP_BAD_INPUT_DATA => Ok(false),
            x => Err(::Error::from_mbedtls_code(x)),
        }
    }

    pub fn to_binary(&self, group: &EcGroup, compressed: bool) -> ::Result<Vec<u8>> {
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

        let format = if compressed {
            ECP_PF_COMPRESSED
        } else {
            ECP_PF_UNCOMPRESSED
        };

        unsafe {
            ecp_point_write_binary(
                &group.inner,
                &self.inner,
                format,
                &mut olen,
                buf.as_mut_ptr(),
                buf.len(),
            )
        }
        .into_result()?;

        assert!(olen <= buf.len());

        buf.truncate(olen);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {

    use bignum::Mpi;
    use ecp::EcGroup;
    use ecp::EcPoint;
    use pk::EcGroupId;

    #[test]
    fn test_ec_group() {
        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();

        assert_eq!(secp256r1.group_id().unwrap(), EcGroupId::SecP256R1);

        let p = secp256r1.p().unwrap().to_binary().unwrap();

        let p256 = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

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
        assert_eq!(pt_uncompressed.len(), 1 + 2 * (bitlen / 8));
        let rec_pt = EcPoint::from_binary(&secp256k1, &pt_uncompressed).unwrap();
        assert_eq!(pt.eq(&rec_pt).unwrap(), true);

        let pt_compressed = pt.to_binary(&secp256k1, true).unwrap();
        assert_eq!(pt_compressed.len(), 1 + bitlen / 8);

        /*
        Mbedtls supports encoding a point to compressed, but does not
        support reading it back, so skip trying to do that.
         */

        let affine_x = pt.x().unwrap();
        assert_eq!(
            affine_x,
            Mpi::from_str("0x1E248FB0AB87942E4B74446F7C9CD151468919B525C108759876F806CA2FFC87")
                .unwrap()
        );
        let affine_y = pt.y().unwrap();
        assert_eq!(
            affine_y,
            Mpi::from_str("0x821F40015051C2E37E85A97D96B83A9948FB108E06C98F5AD2CF275C8A9B004B")
                .unwrap()
        );
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
}
