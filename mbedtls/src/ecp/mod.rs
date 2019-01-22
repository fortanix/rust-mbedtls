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
    fn init() {
        ecp_group_init
    }
    fn drop() {
        ecp_group_free
    }
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
    fn init() {
        ecp_point_init
    }
    fn drop() {
        ecp_point_free
    }
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
        let mut buf = vec![0u8, 133];

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
