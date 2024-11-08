/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::error::{IntoResult, Result, codes};
use mbedtls_sys::*;

define!(
    #[c_ty(md_type_t)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    enum Type {
        None = MD_NONE,
        Md2 = MD_MD2,
        Md4 = MD_MD4,
        Md5 = MD_MD5,
        Sha1 = MD_SHA1,
        Sha224 = MD_SHA224,
        Sha256 = MD_SHA256,
        Sha384 = MD_SHA384,
        Sha512 = MD_SHA512,
        Ripemd = MD_RIPEMD160,
    }
);

impl From<md_type_t> for Type {
    fn from(inner: md_type_t) -> Type {
        match inner {
            MD_NONE => Type::None,
            MD_MD2 => Type::Md2,
            MD_MD4 => Type::Md4,
            MD_MD5 => Type::Md5,
            MD_SHA1 => Type::Sha1,
            MD_SHA224 => Type::Sha224,
            MD_SHA256 => Type::Sha256,
            MD_SHA384 => Type::Sha384,
            MD_SHA512 => Type::Sha512,
            MD_RIPEMD160 => Type::Ripemd,
            _ => panic!("Invalid Md type"),
        }
    }
}

#[derive(Copy, Clone)]
pub struct MdInfo {
    inner: &'static md_info_t,
}

impl Into<Option<MdInfo>> for Type {
    fn into(self) -> Option<MdInfo> {
        unsafe { md_info_from_type(self.into()).as_ref() }.map(|r| MdInfo { inner: r })
    }
}

impl Into<*const md_info_t> for MdInfo {
    fn into(self) -> *const md_info_t {
        self.inner
    }
}

define!(
    #[c_ty(md_context_t)]
    struct Md;
    const init: fn() -> Self = md_init;
    const drop: fn(&mut Self) = md_free;
    impl<'a> Into<ptr> {}
);

impl MdInfo {
    pub fn size(&self) -> usize {
        unsafe { md_get_size(self.inner).into() }
    }
    pub fn get_type(&self) -> Type {
        unsafe { md_get_type(self.inner).into() }
    }
}

impl Clone for Md {
    fn clone(&self) -> Self {
        fn copy_md(md: &Md) -> Result<Md> {
            let mut ctx = Md::init();
            unsafe {
                md_setup(&mut ctx.inner, md.inner.md_info, 0).into_result()?;
                md_starts(&mut ctx.inner).into_result()?;
                md_clone(&mut ctx.inner, &md.inner).into_result()?;
            };
            Ok(ctx)
        }
        copy_md(self).expect("Md::copy success")
    }
}

impl Md {
    pub fn new(md: Type) -> Result<Md> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        let mut ctx = Md::init();
        unsafe {
            md_setup(&mut ctx.inner, md.into(), 0).into_result()?;
            md_starts(&mut ctx.inner).into_result()?;
        }
        Ok(ctx)
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        unsafe { md_update(&mut self.inner, data.as_ptr(), data.len()) }.into_result()?;
        Ok(())
    }

    pub fn finish(mut self, out: &mut [u8]) -> Result<usize> {
        unsafe {
            let olen = (*self.inner.md_info).size as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md_finish(&mut self.inner, out.as_mut_ptr()).into_result()?;
            Ok(olen)
        }
    }

    pub fn hash(mdt: Type, data: &[u8], out: &mut [u8]) -> Result<usize> {
        let mdinfo: MdInfo = match mdt.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            let olen = mdinfo.inner.size as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md(mdinfo.inner, data.as_ptr(), data.len(), out.as_mut_ptr()).into_result()?;
            Ok(olen)
        }
    }
}

#[derive(Clone)]
pub struct Hmac {
    ctx: Md,
}

impl Hmac {
    pub fn new(md: Type, key: &[u8]) -> Result<Hmac> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        let mut ctx = Md::init();
        unsafe {
            md_setup(&mut ctx.inner, md.into(), 1).into_result()?;
            md_hmac_starts(&mut ctx.inner, key.as_ptr(), key.len()).into_result()?;
        }
        Ok(Hmac { ctx })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        unsafe { md_hmac_update(&mut self.ctx.inner, data.as_ptr(), data.len()) }.into_result()?;
        Ok(())
    }

    pub fn finish(mut self, out: &mut [u8]) -> Result<usize> {
        unsafe {
            let olen = (*self.ctx.inner.md_info).size as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md_hmac_finish(&mut self.ctx.inner, out.as_mut_ptr()).into_result()?;
            Ok(olen)
        }
    }

    pub fn hmac(md: Type, key: &[u8], data: &[u8], out: &mut [u8]) -> Result<usize> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            let olen = md.inner.size as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md_hmac(md.inner, key.as_ptr(), key.len(), data.as_ptr(), data.len(), out.as_mut_ptr()).into_result()?;
            Ok(olen)
        }
    }
}

/// The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is specified by RFC 5869.
#[derive(Debug)]
pub struct Hkdf;

impl Hkdf {
    /// This is the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
    ///
    /// # Parameters
    ///
    /// * `md`: A hash function; `MdInfo::from(md).size()` denotes the length of the hash
    ///        function output in bytes.
    /// * `salt`: An salt value (a non-secret random value);
    /// * `ikm`: The input keying material.
    /// * `info`: An optional context and application specific information
    ///          string. This can be a zero-length string.
    /// * `okm`: The output keying material. The length of the output keying material in bytes
    ///          must be less than or equal to 255 * `MdInfo::from(md).size()` bytes.
    ///
    /// # Returns
    ///
    /// * `()` on success.
    /// * [`Error::HkdfBadInputData`] when the parameters are invalid.
    /// * Any `Error::Md*` error for errors returned from the underlying
    ///   MD layer.
    pub fn hkdf(md: Type, salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            hkdf(
                md.inner,
                salt.as_ptr(),
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        }
        .into_result()?;
        Ok(())
    }

    /// This is the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
    ///
    /// # Parameters
    ///
    /// * `md`: A hash function; `MdInfo::from(md).size()` denotes the length of the hash
    ///        function output in bytes.
    /// * `salt`: An optional salt value (a non-secret random value);
    ///          if the salt is not provided, a string of all zeros of
    ///          `MdInfo::from(md).size()` length is used as the salt.
    /// * `ikm`: The input keying material.
    /// * `info`: An optional context and application specific information
    ///          string. This can be a zero-length string.
    /// * `okm`: The output keying material. The length of the output keying material in bytes
    ///          must be less than or equal to 255 * `MdInfo::from(md).size()` bytes.
    ///
    /// # Returns
    ///
    /// * `()` on success.
    /// * [`Error::HkdfBadInputData`] when the parameters are invalid.
    /// * Any `Error::Md*` error for errors returned from the underlying
    ///   MD layer.
    pub fn hkdf_optional_salt(md: Type, maybe_salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            hkdf(
                md.inner,
                maybe_salt.map_or(::core::ptr::null(), |salt| salt.as_ptr()),
                maybe_salt.map_or(0, |salt| salt.len()),
                ikm.as_ptr(),
                ikm.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        }
        .into_result()?;
        Ok(())
    }

    /// Takes the input keying material `ikm` and extracts from it a
    /// fixed-length pseudorandom key `prk`.
    ///
    /// # Warning
    ///
    /// This function should only be used if the security of it has been
    /// studied and established in that particular context (eg. TLS 1.3
    /// key schedule). For standard HKDF security guarantees use
    /// `hkdf` instead.
    ///
    /// # Parameters
    ///
    /// * `md`: A hash function; `MdInfo::from(md).size()` denotes the length of the
    ///         hash function output in bytes.
    /// * `salt`: An optional salt value (a non-secret random value);
    ///           if the salt is not provided, a string of all zeros
    ///           of `MdInfo::from(md).size()` length is used as the salt.
    /// * `ikm`: The input keying material.
    /// * `prk`: The output pseudorandom key of at least `MdInfo::from(md).size()` bytes.
    ///
    /// # Returns
    ///
    /// * `()` on success.
    /// * [`Error::HkdfBadInputData`] when the parameters are invalid.
    /// * Any `Error::Md*` error for errors returned from the underlying
    ///   MD layer.
    pub fn hkdf_extract(md: Type, maybe_salt: Option<&[u8]>, ikm: &[u8], prk: &mut [u8]) -> Result<()> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            hkdf_extract(
                md.inner,
                maybe_salt.map_or(::core::ptr::null(), |salt| salt.as_ptr()),
                maybe_salt.map_or(0, |salt| salt.len()),
                ikm.as_ptr(),
                ikm.len(),
                prk.as_mut_ptr(),
            )
        }
        .into_result()?;
        Ok(())
    }

    /// Expand the supplied `prk` into several additional pseudorandom keys, which is the output of the HKDF.
    ///
    /// # Warning
    ///
    /// This function should only be used if the security of it has been
    /// studied and established in that particular context (eg. TLS 1.3
    /// key schedule). For standard HKDF security guarantees use
    /// `hkdf` instead.
    ///
    /// # Parameters
    ///
    /// * `md`: A hash function; `MdInfo::from(md).size()` denotes the length of the
    ///         hash function output in bytes.
    /// * `prk`: A pseudorandom key of at least `MdInfo::from(md).size()` bytes. `prk` is
    ///          usually the output from the HKDF extract step.
    /// * `info`: An optional context and application specific information
    ///          string. This can be a zero-length string.
    /// * `okm`: The output keying material. The length of the output keying material in bytes
    ///          must be less than or equal to 255 * `MdInfo::from(md).size()` bytes.
    ///
    /// # Returns
    ///
    /// * `()` on success.
    /// * [`Error::HkdfBadInputData`] when the parameters are invalid.
    /// * Any `Error::Md*` error for errors returned from the underlying
    ///   MD layer.
    pub fn hkdf_expand(md: Type, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(codes::MdBadInputData.into()),
        };

        unsafe {
            hkdf_expand(
                md.inner,
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        }
        .into_result()?;
        Ok(())
    }
}

pub fn pbkdf2_hmac(md: Type, password: &[u8], salt: &[u8], iterations: u32, key: &mut [u8]) -> Result<()> {
    let md: MdInfo = match md.into() {
        Some(md) => md,
        None => return Err(codes::MdBadInputData.into()),
    };

    unsafe {
        let mut ctx = Md::init();
        md_setup((&mut ctx).into(), md.into(), 1).into_result()?;
        pkcs5_pbkdf2_hmac(
            (&mut ctx).into(),
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            key.len() as u32,
            key.as_mut_ptr(),
        )
        .into_result()?;
        Ok(())
    }
}

pub fn pbkdf_pkcs12(md: Type, password: &[u8], salt: &[u8], id: u8, iterations: u32, key: &mut [u8]) -> Result<()> {
    unsafe {
        pkcs12_derivation(
            key.as_mut_ptr(),
            key.len(),
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            md.into(),
            id as i32,
            iterations as i32,
        )
        .into_result()?;
        Ok(())
    }
}
