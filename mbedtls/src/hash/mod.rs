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
            let olen = md_get_size(md_info_from_ctx(&self.inner)) as usize;
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
            let olen = md_get_size(mdinfo.inner) as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md(mdinfo.inner, data.as_ptr(), data.len(), out.as_mut_ptr()).into_result()?;
            Ok(olen)
        }
    }
}

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
            let olen = md_get_size(md_info_from_ctx(&self.ctx.inner)) as usize;
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
            let olen = md_get_size(md.inner) as usize;
            if out.len() < olen {
                return Err(codes::MdBadInputData.into());
            }
            md_hmac(
                md.inner,
                key.as_ptr(),
                key.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
            )
            .into_result()?;
            Ok(olen)
        }
    }
}

pub struct Hkdf {
    _ctx: Md,
}

impl Hkdf {
    pub fn hkdf(md: Type, salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<()> {
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
                key.as_mut_ptr(),
                key.len(),
            )
            .into_result()?;
            Ok(())
        }
    }
}

impl Clone for Md {
    fn clone(&self) -> Self {
        fn copy_md(md: &Md) -> Result<Md> {
            let md_type = unsafe { md_get_type(md_info_from_ctx(&md.inner)) };
            let mut m = Md::new(md_type.into())?;
            unsafe { md_clone(&mut m.inner, &md.inner) }.into_result()?;
            Ok(m)
        }
        copy_md(self).expect("Md::copy success")
    }
}

pub fn pbkdf2_hmac(
    md: Type,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key: &mut [u8],
) -> Result<()> {
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
