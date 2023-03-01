/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::iter::FromIterator;
use core::ptr::NonNull;

use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_char, c_void};

use crate::alloc::{List as MbedtlsList, Box as MbedtlsBox};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::error::{Error, IntoResult, Result};
use crate::hash::Type as MdType;
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::rng::Random;
use crate::x509::{self, Crl, Time, VerifyCallback};

extern "C" {
    pub(crate) fn forward_mbedtls_calloc(n: mbedtls_sys::types::size_t, size: mbedtls_sys::types::size_t) -> *mut mbedtls_sys::types::raw_types::c_void;
}

#[cfg(feature = "std")]
use yasna::{BERDecodable, BERReader, ASN1Result, ASN1Error, ASN1ErrorKind, models::ObjectIdentifier};

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
pub enum CertificateVersion {
    V1,
    V2,
    V3
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Extension {
    pub oid: ObjectIdentifier,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[cfg(feature = "std")]
impl BERDecodable for Extension {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            let critical = reader.read_optional(|r| r.read_bool())?.unwrap_or(false);
            let value = reader.next().read_bytes()?;
            Ok(Extension { oid, critical, value })
        })
    }
}


define!(
    #[c_ty(x509_crt)]
    #[repr(transparent)]
    struct Certificate;
    const drop: fn(&mut Self) = x509_crt_free;
    impl<'a> Into<ptr> {}
    impl<'a> UnsafeFrom<ptr> {}
);

unsafe impl Sync for Certificate {}

fn x509_buf_to_vec(buf: &x509_buf) -> Vec<u8> {
    if buf.p.is_null() || buf.len == 0 {
        return vec![];
    }

    let slice = unsafe { core::slice::from_raw_parts(buf.p, buf.len) };
    slice.to_owned()
}

fn x509_time_to_time(tm: &x509_time) -> Result<Time> {
    // ensure casts don't underflow
    if tm.year < 0 || tm.mon < 0 || tm.day < 0 || tm.hour < 0 || tm.min < 0 || tm.sec < 0 {
        return Err(Error::X509InvalidDate);
    }

    Time::new(tm.year as u16, tm.mon as u8, tm.day as u8, tm.hour as u8, tm.min as u8, tm.sec as u8).ok_or(Error::X509InvalidDate)
}


impl Certificate {
    pub fn from_der(der: &[u8]) -> Result<MbedtlsBox<Certificate>> {
        let mut cert = MbedtlsBox::<Certificate>::init()?;
        unsafe { x509_crt_parse_der((&mut (*cert)).into(), der.as_ptr(), der.len()) }.into_result()?;
        Ok(cert)
    }

    /// Input must be NULL-terminated
    pub fn from_pem(pem: &[u8]) -> Result<MbedtlsBox<Certificate>> {
        let mut cert = MbedtlsBox::<Certificate>::init()?;
        unsafe { x509_crt_parse((&mut (*cert)).into(), pem.as_ptr(), pem.len()) }.into_result()?;
        
        if !(*cert).inner.next.is_null() {
            // Use from_pem_multiple for parsing multiple certificates in a pem.
            return Err(Error::X509BadInputData);
        }

        Ok(cert)
    }
    
    /// Input must be NULL-terminated
    pub fn from_pem_multiple(pem: &[u8]) -> Result<MbedtlsList<Certificate>> {
        let mut cert = MbedtlsBox::<Certificate>::init()?;
        unsafe { x509_crt_parse((&mut (*cert)).into(), pem.as_ptr(), pem.len()) }.into_result()?;

        let mut list = MbedtlsList::<Certificate>::new();
        list.push(cert);
        Ok(list)
    }
    
    pub fn check_key_usage(&self, usage: super::KeyUsage) -> bool {
        unsafe { x509_crt_check_key_usage(&self.inner, usage.bits()) }
            .into_result()
            .is_ok()
    }

    pub fn check_extended_key_usage(&self, usage_oid: &[c_char]) -> bool {
        unsafe {
            x509_crt_check_extended_key_usage(&self.inner, usage_oid.as_ptr(), usage_oid.len())
        }
        .into_result()
        .is_ok()
    }

    pub fn issuer(&self) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_dn_gets(buf, size, &self.inner.issuer)
        })
    }

    pub fn issuer_raw(&self) -> Result<Vec<u8>> {
        Ok(x509_buf_to_vec(&self.inner.issuer_raw))
    }

    pub fn subject(&self) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_dn_gets(buf, size, &self.inner.subject)
        })
    }

    pub fn subject_raw(&self) -> Result<Vec<u8>> {
        Ok(x509_buf_to_vec(&self.inner.subject_raw))
    }

    pub fn serial(&self) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_serial_gets(buf, size, &self.inner.serial)
        })
    }

    pub fn serial_raw(&self) -> Result<Vec<u8>> {
        Ok(x509_buf_to_vec(&self.inner.serial))
    }

    pub fn public_key(&self) -> &Pk {
        unsafe { &*(&self.inner.pk as *const _ as *const _) }
    }

    pub fn public_key_mut(&mut self) -> &mut Pk {
        unsafe { &mut *(&mut self.inner.pk as *mut _ as *mut _) }
    }

    pub fn as_der(&self) -> &[u8] {
        unsafe { ::core::slice::from_raw_parts(self.inner.raw.p, self.inner.raw.len) }
    }

    pub fn version(&self) -> Result<CertificateVersion> {
        match self.inner.version {
            1 => Ok(CertificateVersion::V1),
            2 => Ok(CertificateVersion::V2),
            3 => Ok(CertificateVersion::V3),
            _ => Err(Error::X509InvalidVersion)
        }
    }

    pub fn not_before(&self) -> Result<super::Time> {
        x509_time_to_time(&self.inner.valid_from)
    }

    pub fn not_after(&self) -> Result<super::Time> {
        x509_time_to_time(&self.inner.valid_to)
    }

    pub fn extensions_raw(&self) -> Result<Vec<u8>> {
        Ok(x509_buf_to_vec(&self.inner.v3_ext))
    }

    #[cfg(feature = "std")]
    pub fn extensions(&self) -> Result<Vec<Extension>> {
        let mut ext = Vec::new();

        yasna::parse_der(&self.extensions_raw()?, |r| {
            r.read_sequence_of(|r| {
                if let Ok(data) = r.read_der() {
                    let e: Extension = yasna::decode_der(&data)?;
                    ext.push(e);
                    return Ok(());
                } else {
                    return Err(ASN1Error::new(ASN1ErrorKind::Eof));
                }
            })?;
            return Ok(());
        }).map_err(|_| Error::X509InvalidExtensions)?;

        Ok(ext)
    }

    pub fn signature(&self) -> Result<Vec<u8>> {
        Ok(x509_buf_to_vec(&self.inner.sig))
    }

    pub fn digest_type(&self) -> MdType {
        MdType::from(self.inner.sig_md)
    }

    fn verify_ex<F>(
        chain: &MbedtlsList<Certificate>,
        trust_ca: &MbedtlsList<Certificate>,
        ca_crl: Option<&mut Crl>,
        err_info: Option<&mut String>,
        cb: Option<F>,
    ) -> Result<()>
    where
        F: VerifyCallback + 'static,
    {
        let (f_vrfy, p_vrfy): (Option<unsafe extern "C" fn(_, _, _, _) -> _>, _) = if let Some(cb) = cb.as_ref() {
            (Some(x509::verify_callback::<F>),
            cb as *const _ as *mut c_void)
        } else {
            (None, ::core::ptr::null_mut())
        };
        let mut flags = 0;
        let result = unsafe {
            x509_crt_verify(
                chain.inner_ffi_mut(),
                trust_ca.inner_ffi_mut(),
                ca_crl.map_or(::core::ptr::null_mut(), |crl| crl.handle_mut()),
                ::core::ptr::null(),
                &mut flags,
                f_vrfy,
                p_vrfy,
            )
        }
        .into_result();

        if result.is_err() {
            if let Some(err_info) = err_info {
                let verify_info = crate::private::alloc_string_repeat(|buf, size| unsafe {
                    let prefix = "\0";
                    x509_crt_verify_info(buf, size, prefix.as_ptr() as *const _, flags)
                });
                if let Ok(error_str) = verify_info {
                    *err_info = error_str;
                }
            }
        }
        result.map(|_| ())
    }

    pub fn verify(
        chain: &MbedtlsList<Certificate>,
        trust_ca: &MbedtlsList<Certificate>,
        ca_crl: Option<&mut Crl>,
        err_info: Option<&mut String>,
    ) -> Result<()> {
        Self::verify_ex(chain, trust_ca, ca_crl, err_info, None::<&dyn VerifyCallback>)
    }

    pub fn verify_with_callback<F>(
        chain: &MbedtlsList<Certificate>,
        trust_ca: &MbedtlsList<Certificate>,
        ca_crl: Option<&mut Crl>,
        err_info: Option<&mut String>,
        cb: F,
    ) -> Result<()>
    where
        F: VerifyCallback + 'static,
    {
        Self::verify_ex(chain, trust_ca, ca_crl, err_info, Some(cb))
    }
}

// TODO
//
// x509_crt_verify_with_profile
// x509_crt_is_revoked
//
// x509_crt_parse_file
// x509_crt_parse_path
//

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_crt_info(buf, size, b"\0".as_ptr() as *const _, &self.inner)
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

define!(
    #[c_ty(x509write_cert)]
    struct Builder<'a>;
    pub const new: fn() -> Self = x509write_crt_init;
    const drop: fn(&mut Self) = x509write_crt_free;
);

impl<'a> Builder<'a> {
    unsafe fn subject_with_nul_unchecked(&mut self, subject: &[u8]) -> Result<&mut Self> {
        x509write_crt_set_subject_name(&mut self.inner, subject.as_ptr() as *const _).into_result()?;
        Ok(self)
    }

    #[cfg(feature = "std")]
    pub fn subject(&mut self, subject: &str) -> Result<&mut Self> {
        match ::std::ffi::CString::new(subject) {
            Err(_) => Err(Error::X509InvalidName),
            Ok(s) => unsafe { self.subject_with_nul_unchecked(s.as_bytes_with_nul()) },
        }
    }

    pub fn subject_with_nul(&mut self, subject: &str) -> Result<&mut Self> {
        if subject.as_bytes().iter().any(|&c| c == 0) {
            unsafe { self.subject_with_nul_unchecked(subject.as_bytes()) }
        } else {
            Err(Error::X509InvalidName)
        }
    }

    unsafe fn issuer_with_nul_unchecked(&mut self, issuer: &[u8]) -> Result<&mut Self> {
        x509write_crt_set_issuer_name(&mut self.inner, issuer.as_ptr() as *const _).into_result()?;
        Ok(self)
    }

    #[cfg(feature = "std")]
    pub fn issuer(&mut self, issuer: &str) -> Result<&mut Self> {
        match ::std::ffi::CString::new(issuer) {
            Err(_) => Err(Error::X509InvalidName),
            Ok(s) => unsafe { self.issuer_with_nul_unchecked(s.as_bytes_with_nul()) },
        }
    }

    pub fn issuer_with_nul(&mut self, issuer: &str) -> Result<&mut Self> {
        if issuer.as_bytes().iter().any(|&c| c == 0) {
            unsafe { self.issuer_with_nul_unchecked(issuer.as_bytes()) }
        } else {
            Err(Error::X509InvalidName)
        }
    }

    pub fn subject_key(&mut self, key: &'a mut Pk) -> &mut Self {
        unsafe { x509write_crt_set_subject_key(&mut self.inner, key.into()) };
        self
    }

    pub fn issuer_key(&mut self, key: &'a mut Pk) -> &mut Self {
        unsafe { x509write_crt_set_issuer_key(&mut self.inner, key.into()) };
        self
    }

    pub fn signature_hash(&mut self, md: MdType) -> &mut Self {
        unsafe { x509write_crt_set_md_alg(&mut self.inner, md.into()) };
        self
    }

    pub fn key_usage(&mut self, usage: crate::x509::KeyUsage) -> Result<&mut Self> {
        unsafe { x509write_crt_set_key_usage(&mut self.inner, usage.bits()) }.into_result()?;
        Ok(self)
    }

    pub fn extension(&mut self, oid: &[u8], val: &[u8], critical: bool) -> Result<&mut Self> {
        unsafe {
            x509write_crt_set_extension(
                &mut self.inner,
                oid.as_ptr() as *const _,
                oid.len(),
                critical as _,
                val.as_ptr(),
                val.len()
            ) }.into_result()?;
        Ok(self)
    }

    pub fn basic_constraints(&mut self, ca: bool, pathlen: Option<u32>) -> Result<&mut Self> {
        unsafe {
            x509write_crt_set_basic_constraints(
                &mut self.inner,
                ca as _,
                pathlen.unwrap_or(0) as _
            )
        }.into_result()?;
        Ok(self)
    }

    pub fn validity(
        &mut self,
        not_before: super::Time,
        not_after: super::Time,
    ) -> Result<&mut Self> {
        unsafe {
            x509write_crt_set_validity(
                &mut self.inner,
                not_before.to_x509_time().as_ptr() as _,
                not_after.to_x509_time().as_ptr() as _
            )
        }.into_result()?;
        Ok(self)
    }

    pub fn serial(&mut self, serial: &[u8]) -> Result<&mut Self> {
        let serial = crate::bignum::Mpi::from_binary(serial)?;
        unsafe { x509write_crt_set_serial(&mut self.inner, (&serial).into()) }.into_result()?;
        Ok(self)
    }

    pub fn write_der<'buf, F: Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_crt_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()
        } {
            Err(Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_der_vec<F: Random>(&mut self, rng: &mut F) -> Result<Vec<u8>> {
        crate::private::alloc_vec_repeat(
            |buf, size| unsafe {
                x509write_crt_der(&mut self.inner, buf, size, Some(F::call), rng.data_ptr())
            },
            true,
        )
    }

    pub fn write_pem<'buf, F: Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_crt_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()
        } {
            Err(Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_pem_string<F: Random>(&mut self, rng: &mut F) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            match x509write_crt_pem(
                &mut self.inner,
                buf as _,
                size,
                Some(F::call),
                rng.data_ptr(),
            ) {
                0 => crate::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }
}

// TODO
// x509write_crt_set_version
// x509write_crt_set_ns_cert_type
// x509write_crt_set_authority_key_identifier
// x509write_crt_set_subject_key_identifier
//

impl MbedtlsBox<Certificate> {
    fn init() -> Result<Self> {
        unsafe {
            let inner = forward_mbedtls_calloc(1, core::mem::size_of::<x509_crt>()) as *mut x509_crt;

            // If alignment is wrong it means someone pushed their own allocator to mbedtls and that is not functioning correctly.
            assert_eq!(inner.align_offset(core::mem::align_of::<x509_crt>()), 0);

            let inner = NonNull::new(inner).ok_or(Error::X509AllocFailed)?;
            x509_crt_init(inner.as_ptr());
            
            Ok(MbedtlsBox { inner: inner.cast() })
        }
    }
    
    fn list_next(&self) -> Option<&MbedtlsBox<Certificate>> {
        unsafe {
            <&Option<MbedtlsBox<_>> as UnsafeFrom<_>>::from(&(**self).inner.next).unwrap().as_ref()
        }
    }

    fn list_next_mut(&mut self) -> &mut Option<MbedtlsBox<Certificate>> {
        unsafe {
            <&mut Option<MbedtlsBox<_>> as UnsafeFrom<_>>::from(&mut(**self).inner.next).unwrap()
        }
    }
}

impl Clone for MbedtlsBox<Certificate> {
    fn clone(&self) -> MbedtlsBox<Certificate> {
        unsafe {
            let len = (**self).inner.raw.len;
            if len == 0 {
                // We have a certificate that was never initialized.
                //
                // This is not possible from 'mbedtls' side as all certificates are first init then they parse a der/pem.
                // This is also not possible from rust side as all init() calls are followed by parsing.
                unreachable!("Trying to clone an uninitialized certificate.");
            } else {
                // We have a certificate that was already created once, failing the re-parse is a possible memory corruption or bad usage of mbedtls internals.
                Certificate::from_der(core::slice::from_raw_parts((**self).inner.raw.p, len)).expect("Failed re-parsing existing DER")
            }
        }
    }
}

impl<'a> UnsafeFrom<*const *mut x509_crt> for &'a Option<MbedtlsBox<Certificate>> {
    unsafe fn from(ptr: *const *mut x509_crt) -> Option<&'a Option<MbedtlsBox<Certificate>>> {
        (ptr as *const Option<MbedtlsBox<Certificate>>).as_ref()
    }
}

impl<'a> UnsafeFrom<*mut *mut x509_crt> for &'a mut Option<MbedtlsBox<Certificate>> {
    unsafe fn from(ptr: *mut *mut x509_crt) -> Option<&'a mut Option<MbedtlsBox<Certificate>>> {
        (ptr as *mut Option<MbedtlsBox<Certificate>>).as_mut()
    }
}

impl MbedtlsList<Certificate> {
    pub fn new() -> Self {
        Self { inner: None }
    }

    pub(crate) fn into_raw(mut self) -> *mut x509_crt {
        // This leaks a *mut Certificate that we can cast to x509_crt as it's transparent and has no extra fields.
        self.inner.take().map(|x| x.into_raw()).unwrap_or(core::ptr::null_mut()) as *mut x509_crt
    }
    
    pub fn is_empty(&self) -> bool {
        self.inner.is_none()
    }
    
    pub fn push(&mut self, certificate: MbedtlsBox<Certificate>) -> () {
        self.append(MbedtlsList::<Certificate> { inner: Some(certificate) });
    }

    pub fn pop_back(&mut self) -> Option<MbedtlsBox<Certificate>> {
        let mut iter = self.iter_mut();

        let mut prev = iter.next()?;
        for cur in &mut iter {
            if cur.list_next().is_none() {
                return prev.list_next_mut().take();
            }
            prev = cur;
        }
        
        // no iterations in for loop: head equals tail
        self.inner.take()
    }

    
    pub fn pop_front(&mut self) -> Option<MbedtlsBox<Certificate>> {
        let mut ret = self.inner.take()?;
        self.inner = ret.list_next_mut().take();
        Some(ret)
    }


    pub fn append(&mut self, list: MbedtlsList<Certificate>) {
        let tail = match self.iter_mut().last() {
            None => &mut self.inner,
            Some(last) => last.list_next_mut(),
        };
        *tail = list.inner;
    }
    
    pub fn iter(&self) -> Iter<'_> {
        Iter { next: self.inner.as_ref() }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut { next: self.inner.as_mut() }
    }

    pub(crate) unsafe fn inner_ffi_mut(&self) -> *mut x509_crt {
        self.inner.as_ref().map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *mut x509_crt)
    }
}

impl Clone for MbedtlsList<Certificate> {
    fn clone(&self) -> MbedtlsList<Certificate> {
        self.iter().cloned().collect()
    }
}

impl Into<*const x509_crt> for &MbedtlsList<Certificate> {
    fn into(self) -> *const x509_crt {
        self.inner.as_ref().map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *const x509_crt)
    }
}

impl Into<*mut x509_crt> for &mut MbedtlsList<Certificate> {
    fn into(self) -> *mut x509_crt {
        self.inner.as_ref().map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *mut x509_crt)
    }
}

impl<'a> UnsafeFrom<*const *const x509_crt> for &'a MbedtlsList<Certificate> {
    unsafe fn from(ptr: *const *const x509_crt) -> Option<&'a MbedtlsList<Certificate>> {
        if ptr.is_null() || (*ptr).is_null() {
            return None;
        }

        (ptr as *const MbedtlsList<Certificate>).as_ref()
    }
}

impl<'a> UnsafeFrom<*mut *mut x509_crt> for &'a mut MbedtlsList<Certificate> {
    unsafe fn from(ptr: *mut *mut x509_crt) -> Option<&'a mut MbedtlsList<Certificate>> {
        if ptr.is_null() || (*ptr).is_null() {
            return None;
        }

        (ptr as *mut MbedtlsList<Certificate>).as_mut()
    }
}


pub struct Iter<'a> {
    next: Option<&'a MbedtlsBox::<Certificate>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a MbedtlsBox<Certificate>;

    fn next(&mut self) -> Option<&'a MbedtlsBox::<Certificate>> {
        let ret = self.next.take()?;
        self.next = ret.list_next();
        Some(ret)
    }
}

pub struct IterMut<'a> {
    next: Option<&'a mut MbedtlsBox::<Certificate>>,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut MbedtlsBox<Certificate>;

    fn next(&mut self) -> Option<&'a mut MbedtlsBox::<Certificate>> {
        let ret = self.next.take()?;
        unsafe {
            self.next = <&mut Option<MbedtlsBox<_>> as UnsafeFrom<_>>::from(&mut (**ret).inner.next).and_then(|v| v.as_mut());
        }
        Some(ret)
    }
}

// Follows same pattern as IntoIter from rust-lang's linked_list.rs
// - line 108: https://github.com/rust-lang/rust/blob/master/library/alloc/src/collections/linked_list.rs
pub struct IntoIter {
    list: MbedtlsList<Certificate>,
}

impl Iterator for IntoIter {
    type Item = MbedtlsBox<Certificate>;

    #[inline]
    fn next(&mut self) -> Option<MbedtlsBox<Certificate>> {
        self.list.pop_front()
    }
}

impl IntoIterator for MbedtlsList<Certificate> {
    type Item = MbedtlsBox<Certificate>;
    type IntoIter = IntoIter;

    /// Consumes the list into an iterator yielding elements by value.
    #[inline]
    fn into_iter(self) -> IntoIter {
        IntoIter { list: self }
    }
}

impl<'a> IntoIterator for &'a MbedtlsList<Certificate> {
    type Item = &'a MbedtlsBox::<Certificate>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut MbedtlsList<Certificate> {
    type Item = &'a mut MbedtlsBox<Certificate>;
    type IntoIter = IterMut<'a>;

    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

impl FromIterator<MbedtlsBox::<Certificate>> for MbedtlsList<Certificate> {
    fn from_iter<I: IntoIterator<Item = MbedtlsBox::<Certificate>>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

impl Extend<MbedtlsBox::<Certificate>> for MbedtlsList<Certificate> {
    fn extend<I: IntoIterator<Item = MbedtlsBox::<Certificate>>>(&mut self, iter: I) {
        iter.into_iter().for_each(move |elt| self.push(elt));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::VerifyError;

    struct Test {
        key1: Pk,
        key2: Pk,
    }

    impl Test {
        fn new() -> Self {
            Test {
                key1: Pk::from_private_key(crate::test_support::keys::PEM_SELF_SIGNED_KEY, None).unwrap(),
                key2: Pk::from_private_key(crate::test_support::keys::PEM_SELF_SIGNED_KEY, None).unwrap(),
            }
        }

        fn builder<'a>(&'a mut self) -> Builder<'a> {
            let mut b = Builder::new();
            b.subject_key(&mut self.key1)
                .subject_with_nul("CN=mbedtls.example\0")
                .unwrap()
                .issuer_key(&mut self.key2)
                .issuer_with_nul("CN=mbedtls.example\0")
                .unwrap()
                .validity(
                    Time::new(2000, 1, 1, 0, 0, 0).unwrap(),
                    Time::new(2009, 12, 31, 23, 59, 59).unwrap(),
                )
                .unwrap();
            b
        }
    }

    const TEST_PEM: &'static str = r"-----BEGIN CERTIFICATE-----
MIICsTCCAZmgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9tYmVk
dGxzLmV4YW1wbGUwHhcNMDAwMTAxMDAwMDAwWhcNMDkxMjMxMjM1OTU5WjAaMRgw
FgYDVQQDDA9tYmVkdGxzLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDFjAgmCJUmKAQ/OAg0MBh3E2+l5asSHdBNmTm0gr3vmnmFcUqlIpUG
3BGd85o0c9X5qnxBKJafTJLu2xRqjx1TMlBdtVpP0CXy5qPYwvO8UWIGyrsniy8G
fpDjXGkUFbm91Cw1c/lCD7R16lLHK+7Npq9oxpk3KfMHivQorFd31byo0VxZv/sF
YViCbDtOYmMifQX/qkqsbvkxSuPklzpxAxF824mtKMRimwGQbZ4tbLlAFNugO02e
V0Hq8xHxfbmNrblSqIy68/Udjg4Y9feFi8NVfYg/rsFjuL+Fv/3dLBBhaMffyV9J
0eULXgVw5ZXNaQgKb6sSBQqiU3LftHDTAgMBAAGjAjAAMA0GCSqGSIb3DQEBCwUA
A4IBAQAEfQ3N4I9+tWOltiVumy3JaJNyw4LhtOwM4TSjvHFq/sNqCQMuA3ixXgS0
pPjcURyEnH46tEBR9dLonAVGguusVcUjsHyfpgzda7VlAg6OI8l5XnujiLhf8b/D
m1X5f8kDP5ob0hbWo4YIssLH1FN0AMF9FtUyeoYjTtE56fG2uLIVYnIApTRvhrFa
wtfutqbhaHaSyMNuh2Apt7lozJfbfZ/2SJv69s+dFLMyZNNAh2DI8s+9XTEIs787
JeRsNCbrxuEPG6p06ofrO68zdn1ZOksOlUoPy4X3DVKEipnBtyUfqbIr6uWvDsko
JS7pkcufTIoN0Yj0SxAWLW711FgB
-----END CERTIFICATE-----
";

    const TEST_DER: &'static [u8] = &[
        0x30, 0x82, 0x02, 0xb1, 0x30, 0x82, 0x01, 0x99, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
        0x05, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
        0x00, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x6d,
        0x62, 0x65, 0x64, 0x74, 0x6c, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30,
        0x1e, 0x17, 0x0d, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x17, 0x0d, 0x30, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
        0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x6d,
        0x62, 0x65, 0x64, 0x74, 0x6c, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30,
        0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
        0x01, 0x00, 0xc5, 0x8c, 0x08, 0x26, 0x08, 0x95, 0x26, 0x28, 0x04, 0x3f, 0x38, 0x08, 0x34,
        0x30, 0x18, 0x77, 0x13, 0x6f, 0xa5, 0xe5, 0xab, 0x12, 0x1d, 0xd0, 0x4d, 0x99, 0x39, 0xb4,
        0x82, 0xbd, 0xef, 0x9a, 0x79, 0x85, 0x71, 0x4a, 0xa5, 0x22, 0x95, 0x06, 0xdc, 0x11, 0x9d,
        0xf3, 0x9a, 0x34, 0x73, 0xd5, 0xf9, 0xaa, 0x7c, 0x41, 0x28, 0x96, 0x9f, 0x4c, 0x92, 0xee,
        0xdb, 0x14, 0x6a, 0x8f, 0x1d, 0x53, 0x32, 0x50, 0x5d, 0xb5, 0x5a, 0x4f, 0xd0, 0x25, 0xf2,
        0xe6, 0xa3, 0xd8, 0xc2, 0xf3, 0xbc, 0x51, 0x62, 0x06, 0xca, 0xbb, 0x27, 0x8b, 0x2f, 0x06,
        0x7e, 0x90, 0xe3, 0x5c, 0x69, 0x14, 0x15, 0xb9, 0xbd, 0xd4, 0x2c, 0x35, 0x73, 0xf9, 0x42,
        0x0f, 0xb4, 0x75, 0xea, 0x52, 0xc7, 0x2b, 0xee, 0xcd, 0xa6, 0xaf, 0x68, 0xc6, 0x99, 0x37,
        0x29, 0xf3, 0x07, 0x8a, 0xf4, 0x28, 0xac, 0x57, 0x77, 0xd5, 0xbc, 0xa8, 0xd1, 0x5c, 0x59,
        0xbf, 0xfb, 0x05, 0x61, 0x58, 0x82, 0x6c, 0x3b, 0x4e, 0x62, 0x63, 0x22, 0x7d, 0x05, 0xff,
        0xaa, 0x4a, 0xac, 0x6e, 0xf9, 0x31, 0x4a, 0xe3, 0xe4, 0x97, 0x3a, 0x71, 0x03, 0x11, 0x7c,
        0xdb, 0x89, 0xad, 0x28, 0xc4, 0x62, 0x9b, 0x01, 0x90, 0x6d, 0x9e, 0x2d, 0x6c, 0xb9, 0x40,
        0x14, 0xdb, 0xa0, 0x3b, 0x4d, 0x9e, 0x57, 0x41, 0xea, 0xf3, 0x11, 0xf1, 0x7d, 0xb9, 0x8d,
        0xad, 0xb9, 0x52, 0xa8, 0x8c, 0xba, 0xf3, 0xf5, 0x1d, 0x8e, 0x0e, 0x18, 0xf5, 0xf7, 0x85,
        0x8b, 0xc3, 0x55, 0x7d, 0x88, 0x3f, 0xae, 0xc1, 0x63, 0xb8, 0xbf, 0x85, 0xbf, 0xfd, 0xdd,
        0x2c, 0x10, 0x61, 0x68, 0xc7, 0xdf, 0xc9, 0x5f, 0x49, 0xd1, 0xe5, 0x0b, 0x5e, 0x05, 0x70,
        0xe5, 0x95, 0xcd, 0x69, 0x08, 0x0a, 0x6f, 0xab, 0x12, 0x05, 0x0a, 0xa2, 0x53, 0x72, 0xdf,
        0xb4, 0x70, 0xd3, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x02, 0x30, 0x00, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
        0x01, 0x00, 0x04, 0x7d, 0x0d, 0xcd, 0xe0, 0x8f, 0x7e, 0xb5, 0x63, 0xa5, 0xb6, 0x25, 0x6e,
        0x9b, 0x2d, 0xc9, 0x68, 0x93, 0x72, 0xc3, 0x82, 0xe1, 0xb4, 0xec, 0x0c, 0xe1, 0x34, 0xa3,
        0xbc, 0x71, 0x6a, 0xfe, 0xc3, 0x6a, 0x09, 0x03, 0x2e, 0x03, 0x78, 0xb1, 0x5e, 0x04, 0xb4,
        0xa4, 0xf8, 0xdc, 0x51, 0x1c, 0x84, 0x9c, 0x7e, 0x3a, 0xb4, 0x40, 0x51, 0xf5, 0xd2, 0xe8,
        0x9c, 0x05, 0x46, 0x82, 0xeb, 0xac, 0x55, 0xc5, 0x23, 0xb0, 0x7c, 0x9f, 0xa6, 0x0c, 0xdd,
        0x6b, 0xb5, 0x65, 0x02, 0x0e, 0x8e, 0x23, 0xc9, 0x79, 0x5e, 0x7b, 0xa3, 0x88, 0xb8, 0x5f,
        0xf1, 0xbf, 0xc3, 0x9b, 0x55, 0xf9, 0x7f, 0xc9, 0x03, 0x3f, 0x9a, 0x1b, 0xd2, 0x16, 0xd6,
        0xa3, 0x86, 0x08, 0xb2, 0xc2, 0xc7, 0xd4, 0x53, 0x74, 0x00, 0xc1, 0x7d, 0x16, 0xd5, 0x32,
        0x7a, 0x86, 0x23, 0x4e, 0xd1, 0x39, 0xe9, 0xf1, 0xb6, 0xb8, 0xb2, 0x15, 0x62, 0x72, 0x00,
        0xa5, 0x34, 0x6f, 0x86, 0xb1, 0x5a, 0xc2, 0xd7, 0xee, 0xb6, 0xa6, 0xe1, 0x68, 0x76, 0x92,
        0xc8, 0xc3, 0x6e, 0x87, 0x60, 0x29, 0xb7, 0xb9, 0x68, 0xcc, 0x97, 0xdb, 0x7d, 0x9f, 0xf6,
        0x48, 0x9b, 0xfa, 0xf6, 0xcf, 0x9d, 0x14, 0xb3, 0x32, 0x64, 0xd3, 0x40, 0x87, 0x60, 0xc8,
        0xf2, 0xcf, 0xbd, 0x5d, 0x31, 0x08, 0xb3, 0xbf, 0x3b, 0x25, 0xe4, 0x6c, 0x34, 0x26, 0xeb,
        0xc6, 0xe1, 0x0f, 0x1b, 0xaa, 0x74, 0xea, 0x87, 0xeb, 0x3b, 0xaf, 0x33, 0x76, 0x7d, 0x59,
        0x3a, 0x4b, 0x0e, 0x95, 0x4a, 0x0f, 0xcb, 0x85, 0xf7, 0x0d, 0x52, 0x84, 0x8a, 0x99, 0xc1,
        0xb7, 0x25, 0x1f, 0xa9, 0xb2, 0x2b, 0xea, 0xe5, 0xaf, 0x0e, 0xc9, 0x28, 0x25, 0x2e, 0xe9,
        0x91, 0xcb, 0x9f, 0x4c, 0x8a, 0x0d, 0xd1, 0x88, 0xf4, 0x4b, 0x10, 0x16, 0x2d, 0x6e, 0xf5,
        0xd4, 0x58, 0x01,
    ];

    #[test]
    fn write_der() {
        let mut t = Test::new();
        let output = t
            .builder()
            .serial(&[5]).unwrap()
            .signature_hash(MdType::Sha256)
            .write_der_vec(&mut crate::test_support::rand::test_rng())
            .unwrap();
        assert!(output == TEST_DER);
    }

    #[test]
    fn write_pem() {
        let mut t = Test::new();
        let output = t
            .builder()
            .serial(&[5]).unwrap()
            .signature_hash(MdType::Sha256)
            .write_pem_string(&mut crate::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(output, TEST_PEM);
    }

    
    const TEST_CERT_PEM: &'static str = "-----BEGIN CERTIFICATE-----
MIIDLDCCAhSgAwIBAgIRALY0SS5pY9Yb/aIHvSAvmOswDQYJKoZIhvcNAQELBQAw
HzEQMA4GA1UEAxMHVGVzdCBDQTELMAkGA1UEBhMCVVMwHhcNMTkwMTA4MDAxODM1
WhcNMjkwMTA1MDAxODM1WjAjMRIwEAYDVQQDEwlUZXN0IENlcnQxDTALBgNVBAoT
BFRlc3Qwgd8wDQYJKoZIhvcNAQEBBQADgc0AMIHJAoHBAKYINzSAKG1/Kn/5dWXq
cfJgfQkzVn1HPzdb4NNZL+H7woGuzDGrcQ7EPi7r4EuAEE2fCjhSfiYlacoBOxd/
k9Fp4Iv2ygCY1nj8RY0tFCZcZDVYj5F7uqyJMf7+QSOpnZ4cb3zdj1HkBmq7ac0C
7tXkubvM6gBS3H3XlhfszcEjvhavaxVVoitdqW8RJ2DHvqGwFUxPgFCuuQudeCI/
UzBiPMRqu3Pr9Xhcc0ruG5SkCg5isbWWnKNj7X1gTre6WwIDAQABo4GiMIGfMCEG
A1UdDgQaBBhoOfrVfmVEEhzGvEIZU8yWIGVcV8+sBgIwMgYDVR0RBCswKYERdGVz
dEBmb3J0YW5peC5jb22CFGV4YW1wbGUuZm9ydGFuaXguY29tMAwGA1UdEwEB/wQC
MAAwIwYDVR0jBBwwGoAYeQdrzI2gB35BFvhLjkycXGr37E+gANmHMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBKSyY45jagwBIbAzTgSzQq
wXsXixowANXchMBhKUFRnjrJnacoI4CeZD+dHA/3yic0xjl0IVh59ihlMtQ7DaYI
b7ISqWyPVz3kIwyas64J1iFxnS41s+kZY9XnY6Jz8OJda7xfzQzXrOaIgh3xck+z
lWyWBGzVgSbzripmaAzMyKrsvmgPpfx5aE7zP2QVOzGXE/QuoXqj/bmblNlUZu11
5XJ4nSxziKSdNaZZBCn+m2lZiW6GWK7idvNHT/MVBR5mM74jbSrPVSFk6mk2Ei+d
cYp0bH/RcPTC0Z+ZaqSWMtfxRrk63MJQF9EXpDCdvQRcTMD9D85DJrMKn8aumq0M
-----END CERTIFICATE-----\0";

    #[test]
    fn cert_field_access() {
        let cert = Certificate::from_pem(TEST_CERT_PEM.as_bytes()).unwrap();
        
        assert_eq!(cert.version().unwrap(), CertificateVersion::V3);
        assert_eq!(cert.issuer().unwrap(), "CN=Test CA, C=US");
        assert_eq!(cert.subject().unwrap(), "CN=Test Cert, O=Test");
        assert_eq!(
            cert.serial().unwrap(),
            "B6:34:49:2E:69:63:D6:1B:FD:A2:07:BD:20:2F:98:EB"
        );
        assert_eq!(cert.digest_type(), MdType::Sha256);

        assert_eq!(hex::encode(cert.serial_raw().unwrap()), "00b634492e6963d61bfda207bd202f98eb");
        assert_eq!(hex::encode(cert.issuer_raw().unwrap()), "301f3110300e0603550403130754657374204341310b3009060355040613025553");
        assert_eq!(hex::encode(cert.subject_raw().unwrap()), "30233112301006035504031309546573742043657274310d300b060355040a130454657374");
        assert_eq!(hex::encode(cert.signature().unwrap()), "4a4b2638e636a0c0121b0334e04b342ac17b178b1a3000d5dc84c0612941519e3ac99da72823809e643f9d1c0ff7ca2734c63974215879f6286532d43b0da6086fb212a96c8f573de4230c9ab3ae09d621719d2e35b3e91963d5e763a273f0e25d6bbc5fcd0cd7ace688821df1724fb3956c96046cd58126f3ae2a66680cccc8aaecbe680fa5fc79684ef33f64153b319713f42ea17aa3fdb99b94d95466ed75e572789d2c7388a49d35a6590429fe9b6959896e8658aee276f3474ff315051e6633be236d2acf552164ea6936122f9d718a746c7fd170f4c2d19f996aa49632d7f146b93adcc25017d117a4309dbd045c4cc0fd0fce4326b30a9fc6ae9aad0c");
        assert_eq!(hex::encode(cert.extensions_raw().unwrap()), "30819f30210603551d0e041a04186839fad57e6544121cc6bc421953cc9620655c57cfac060230320603551d11042b302981117465737440666f7274616e69782e636f6d82146578616d706c652e666f7274616e69782e636f6d300c0603551d130101ff0402300030230603551d23041c301a801879076bcc8da0077e4116f84b8e4c9c5c6af7ec4fa000d98730130603551d25040c300a06082b06010505070302");

        assert_eq!(cert.not_before().unwrap(), Time::new(2019,1,8,0,18,35).unwrap());
        assert_eq!(cert.not_after().unwrap(), Time::new(2029,1,5,0,18,35).unwrap());

        #[cfg(feature = "std")] {
            let ext = cert.extensions().unwrap();
            assert_eq!(ext.len(), 5);

            assert_eq!(ext[0], Extension {
                oid: ObjectIdentifier::from_slice(&[2,5,29,14]),
                critical: false,
                value: hex::decode("04186839FAD57E6544121CC6BC421953CC9620655C57CFAC0602").unwrap(),
            });
            assert_eq!(ext[1], Extension {
                oid: ObjectIdentifier::from_slice(&[2,5,29,17]),
                critical: false,
                value: hex::decode("302981117465737440666f7274616e69782e636f6d82146578616d706c652e666f7274616e69782e636f6d").unwrap()
            });
            assert_eq!(ext[2], Extension {
                oid: ObjectIdentifier::from_slice(&[2,5,29,19]),
                critical: true,
                value: hex::decode("3000").unwrap()
            });
            assert_eq!(ext[3], Extension {
                oid: ObjectIdentifier::from_slice(&[2,5,29,35]),
                critical: false,
                value: hex::decode("301a801879076BCC8DA0077E4116F84B8E4C9C5C6AF7EC4FA000D987").unwrap()
            });
            assert_eq!(ext[4], Extension {
                oid: ObjectIdentifier::from_slice(&[2,5,29,37]),
                critical: false,
                value: hex::decode("300a06082b06010505070302").unwrap(),
            });
        }
    }

    #[test]
    fn channel_binding_hash() {
        const TEST_CERT_PEM: &'static str = "-----BEGIN CERTIFICATE-----
MIIDLDCCAhSgAwIBAgIRALY0SS5pY9Yb/aIHvSAvmOswDQYJKoZIhvcNAQELBQAw
HzEQMA4GA1UEAxMHVGVzdCBDQTELMAkGA1UEBhMCVVMwHhcNMTkwMTA4MDAxODM1
WhcNMjkwMTA1MDAxODM1WjAjMRIwEAYDVQQDEwlUZXN0IENlcnQxDTALBgNVBAoT
BFRlc3Qwgd8wDQYJKoZIhvcNAQEBBQADgc0AMIHJAoHBAKYINzSAKG1/Kn/5dWXq
cfJgfQkzVn1HPzdb4NNZL+H7woGuzDGrcQ7EPi7r4EuAEE2fCjhSfiYlacoBOxd/
k9Fp4Iv2ygCY1nj8RY0tFCZcZDVYj5F7uqyJMf7+QSOpnZ4cb3zdj1HkBmq7ac0C
7tXkubvM6gBS3H3XlhfszcEjvhavaxVVoitdqW8RJ2DHvqGwFUxPgFCuuQudeCI/
UzBiPMRqu3Pr9Xhcc0ruG5SkCg5isbWWnKNj7X1gTre6WwIDAQABo4GiMIGfMCEG
A1UdDgQaBBhoOfrVfmVEEhzGvEIZU8yWIGVcV8+sBgIwMgYDVR0RBCswKYERdGVz
dEBmb3J0YW5peC5jb22CFGV4YW1wbGUuZm9ydGFuaXguY29tMAwGA1UdEwEB/wQC
MAAwIwYDVR0jBBwwGoAYeQdrzI2gB35BFvhLjkycXGr37E+gANmHMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBKSyY45jagwBIbAzTgSzQq
wXsXixowANXchMBhKUFRnjrJnacoI4CeZD+dHA/3yic0xjl0IVh59ihlMtQ7DaYI
b7ISqWyPVz3kIwyas64J1iFxnS41s+kZY9XnY6Jz8OJda7xfzQzXrOaIgh3xck+z
lWyWBGzVgSbzripmaAzMyKrsvmgPpfx5aE7zP2QVOzGXE/QuoXqj/bmblNlUZu11
5XJ4nSxziKSdNaZZBCn+m2lZiW6GWK7idvNHT/MVBR5mM74jbSrPVSFk6mk2Ei+d
cYp0bH/RcPTC0Z+ZaqSWMtfxRrk63MJQF9EXpDCdvQRcTMD9D85DJrMKn8aumq0M
-----END CERTIFICATE-----\0";

        let list = Certificate::from_pem_multiple(&TEST_CERT_PEM.as_bytes()).unwrap();

        let mut iter = list.iter();
        let cert = iter.next().unwrap();
        
        let pk = cert.public_key();

        assert_eq!(pk.pk_type(), crate::pk::Type::Rsa);
        assert_eq!(pk.rsa_public_exponent().unwrap(), 0x10001);

        let channel_binding_hash = match cert.digest_type() {
            MdType::Md5 | MdType::Sha1 => MdType::Sha256,
            digest => digest,
        };

        let mut digest = [0u8; 64];
        let digest_len =
            crate::hash::Md::hash(channel_binding_hash, cert.as_der(), &mut digest).unwrap();

        assert_eq!(
            digest[0..digest_len],
            [
                0xcc, 0x61, 0xd9, 0x07, 0xc2, 0xcb, 0x49, 0x58, 0x73, 0xbf, 0xd7, 0x43, 0x21, 0xb2,
                0xd4, 0x30, 0xc6, 0xfe, 0xa6, 0x6c, 0x28, 0x96, 0x23, 0xc6, 0x28, 0x4c, 0xdd, 0x14,
                0xda, 0x1d, 0xc4, 0x17
            ]
        );
    }

    #[test]
    fn verify_chain() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");
        const C_ROOT: &'static str = concat!(include_str!("../../tests/data/chain-root.crt"),"\0");

        let c_leaf = Certificate::from_pem(C_LEAF.as_bytes()).unwrap();
        let c_int1 = Certificate::from_pem(C_INT1.as_bytes()).unwrap();
        let c_int2 = Certificate::from_pem(C_INT2.as_bytes()).unwrap();
        let mut c_root = Certificate::from_pem_multiple(C_ROOT.as_bytes()).unwrap();
        
        {
            let mut chain = MbedtlsList::<Certificate>::new();
            chain.push(c_leaf.clone());
            chain.push(c_int1.clone());

            let err = Certificate::verify(&chain, &mut c_root, None, None).unwrap_err();
            assert_eq!(err, Error::X509CertVerifyFailed);

            // try again after fixing the chain
            chain.push(c_int2.clone());


            let mut err_str = String::new();

            let verify_callback = |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
                verify_flags.remove(VerifyError::CERT_EXPIRED);
                Ok(())
            };

            Certificate::verify(&chain, &mut c_root, None, None).unwrap();
            let res = Certificate::verify_with_callback(&chain, &mut c_root, None, Some(&mut err_str), verify_callback);

            match res {
                Ok(()) => (),
                Err(e) => assert!(false, "Failed to verify, error: {}, err_str: {}", e, err_str),
            };
        }

        {
            let mut chain = MbedtlsList::<Certificate>::new();
            chain.push(c_leaf.clone());
            chain.push(c_int1.clone());
            chain.push(c_int2.clone());

            Certificate::verify(&chain, &mut c_root, None, None).unwrap();

            let verify_callback = |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
                verify_flags.remove(VerifyError::CERT_EXPIRED);
                Ok(())
            };

            let mut err_str = String::new();
            let res = Certificate::verify_with_callback(&chain, &mut c_root, None, Some(&mut err_str), verify_callback);

            match res {
                Ok(()) => (),
                Err(e) => assert!(false, "Failed to verify, error: {}, err_str: {}", e, err_str),
            };
        }
    }

    
    
    #[test]
    fn clone_test() {
        let cert_chain = Certificate::from_pem(TEST_CERT_PEM.as_bytes()).unwrap();

        let mut chain = MbedtlsList::<Certificate>::new();
        chain.push(cert_chain.clone());
        chain.push(cert_chain.clone());
        chain.push(cert_chain);
        
        let clone = chain.clone();
        let mut it = clone.iter();

        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_none());
        assert!(it.next().is_none());

        let mut it = chain.iter();
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_none());
        assert!(it.next().is_none());
    }


    #[test]
    fn list_pop_back_test() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let c1 = Certificate::from_pem_multiple(C_LEAF.as_bytes()).unwrap();
        let c2 = Certificate::from_pem_multiple(C_INT1.as_bytes()).unwrap();
        let c3 = Certificate::from_pem_multiple(C_INT2.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", c1.iter().next().unwrap());
        let c2_info = format!("{:?}", c2.iter().next().unwrap());
        let c3_info = format!("{:?}", c3.iter().next().unwrap());
        
        chain.append(c1.clone());
        chain.append(c2.clone());
        chain.append(c3.clone());

        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c3_info, format!("{:?}", chain.pop_back().unwrap()));
        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }
        
        chain.append(c3.clone());
        chain.append(c1.clone());
        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c1_info, format!("{:?}", chain.pop_back().unwrap()));
        assert_eq!(c3_info, format!("{:?}", chain.pop_back().unwrap()));
        assert_eq!(c2_info, format!("{:?}", chain.pop_back().unwrap()));

        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c1_info, format!("{:?}", chain.pop_back().unwrap()));

        {
            let mut it = chain.iter();
            assert!(it.next().is_none());
        }
        
        assert!(chain.pop_back().is_none());
        {
            let mut it = chain.iter();
            assert!(it.next().is_none());
        }

        chain.append(c3.clone());
        chain.append(c1.clone());
        {
            let mut it = chain.iter();
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }
    }


    #[test]
    fn list_pop_front_test() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let c1 = Certificate::from_pem(C_LEAF.as_bytes()).unwrap();
        let c2 = Certificate::from_pem(C_INT1.as_bytes()).unwrap();
        let c3 = Certificate::from_pem(C_INT2.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", c1);
        let c2_info = format!("{:?}", c2);
        let c3_info = format!("{:?}", c3);
        
        chain.push(c1.clone());
        chain.push(c2.clone());
        chain.push(c3.clone());

        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c1_info, format!("{:?}", chain.pop_front().unwrap()));
        {
            let mut it = chain.iter();
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }
        
        chain.push(c3.clone());
        chain.push(c1.clone());
        {
            let mut it = chain.iter();
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c2_info, format!("{:?}", chain.pop_front().unwrap()));
        assert_eq!(c3_info, format!("{:?}", chain.pop_front().unwrap()));
        assert_eq!(c3_info, format!("{:?}", chain.pop_front().unwrap()));

        {
            let mut it = chain.iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        assert_eq!(c1_info, format!("{:?}", chain.pop_front().unwrap()));

        {
            let mut it = chain.iter();
            assert!(it.next().is_none());
        }
        
        assert!(chain.pop_front().is_none());
        {
            let mut it = chain.iter();
            assert!(it.next().is_none());
        }

        chain.push(c3.clone());
        chain.push(c1.clone());
        {
            let mut it = chain.iter();
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }
    }


    #[test]
    fn list_clone_test1() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let c1 = Certificate::from_pem_multiple(C_LEAF.as_bytes()).unwrap();
        let c2 = Certificate::from_pem_multiple(C_INT1.as_bytes()).unwrap();
        let c3 = Certificate::from_pem_multiple(C_INT2.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", c1.iter().next().unwrap());
        let c2_info = format!("{:?}", c2.iter().next().unwrap());
        let c3_info = format!("{:?}", c3.iter().next().unwrap());

        chain.append(c1.clone());
        chain.append(c2.clone());
        chain.append(c3.clone());

        chain.append(chain.clone());
        {
            let it_clone = chain.clone();
            let mut it = it_clone.iter();

            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));

            assert!(it.next().is_none());
            assert!(it.next().is_none());
            assert!(it.next().is_none());
        }
    }

    #[test]
    fn list_into_iter() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let c1 = Certificate::from_pem_multiple(C_LEAF.as_bytes()).unwrap();
        let c2 = Certificate::from_pem_multiple(C_INT1.as_bytes()).unwrap();
        let c3 = Certificate::from_pem_multiple(C_INT2.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", c1.iter().next().unwrap());
        let c2_info = format!("{:?}", c2.iter().next().unwrap());
        let c3_info = format!("{:?}", c3.iter().next().unwrap());

        chain.append(c1.clone());
        chain.append(c2.clone());
        chain.append(c3.clone());

        {
            let mut it = chain.clone().into_iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        let clone = chain.clone();
        
        {
            let mut it = chain.into_iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }

        {
            let mut it = clone.into_iter();
            assert_eq!(c1_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c2_info, format!("{:?}", it.next().unwrap()));
            assert_eq!(c3_info, format!("{:?}", it.next().unwrap()));
            assert!(it.next().is_none());
        }
    }



    #[test]
    fn unsafefrom_ptr_checks_test() {
        let mut ptr : *mut x509_crt = ::core::ptr::null_mut() as *mut x509_crt;
        let ptr_test : *mut *mut x509_crt = &mut ptr as *mut *mut x509_crt;

        let option = unsafe {
            <&mut Option<MbedtlsBox<_>> as UnsafeFrom<_>>::from(ptr_test).unwrap()
        };
        assert!(option.is_none());
        
        let cert_list : Option<&mut MbedtlsList<Certificate>> = unsafe { UnsafeFrom::from(ptr_test) };
        assert!(cert_list.is_none());


        let ptr_test : *mut *mut x509_crt = ::core::ptr::null_mut() as *mut *mut x509_crt;
        let cert_list : Option<&mut MbedtlsList<Certificate>> = unsafe { UnsafeFrom::from(ptr_test) };
        assert!(cert_list.is_none());


        
    }

    #[test]
    fn mbedtls_list_to_box_iter_clone() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");
        const C_INT1: &'static str = concat!(include_str!("../../tests/data/chain-int1.crt"),"\0");
        const C_INT2: &'static str = concat!(include_str!("../../tests/data/chain-int2.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let c1 = Certificate::from_pem(C_LEAF.as_bytes()).unwrap();
        let c2 = Certificate::from_pem(C_INT1.as_bytes()).unwrap();
        let c3 = Certificate::from_pem(C_INT2.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", c1);
        
        chain.push(c1.clone());
        chain.push(c2.clone());
        chain.push(c3.clone());

        let cert : &MbedtlsBox::<Certificate> = chain.iter().next().unwrap();

        // First item reference within a list of 3 elements still has next set.
        assert_ne!((**cert).inner.next, ::core::ptr::null_mut());
        assert_eq!(c1_info, format!("{:?}", cert));

        let cert = cert.clone();

        // Cloning it strips it away from the list and forces the next to be null
        assert_eq!((*cert).inner.next, ::core::ptr::null_mut());
        assert_eq!(c1_info, format!("{:?}", cert));

        
        let cert = chain.clone().into_iter().next().unwrap();

        // Using into_iter and extracting a certificate must have its next set to null
        assert_eq!((*cert).inner.next, ::core::ptr::null_mut());
        assert_eq!(c1_info, format!("{:?}", cert));
    }

    #[test]
    fn mbedtls_list_into_test() {
        const C_LEAF: &'static str = concat!(include_str!("../../tests/data/chain-leaf.crt"),"\0");

        let mut chain = MbedtlsList::<Certificate>::new();

        let ptr : *const x509_crt = (&chain).into();
        assert_eq!(ptr, ::core::ptr::null());

        let ptr : *mut x509_crt = (&mut chain).into();
        assert_eq!(ptr, ::core::ptr::null_mut());

        let c1 = Certificate::from_pem(C_LEAF.as_bytes()).unwrap();

        // Using debug strings so failing unit tests can identify any issue with contents.
        let c1_info = format!("{:?}", *c1);
        chain.push(c1.clone());

        let ptr : *const x509_crt = (&chain).into();
        assert_ne!(ptr, ::core::ptr::null());

        let cert : &Certificate = unsafe { UnsafeFrom::from(ptr).unwrap() };
        assert_eq!(c1_info, format!("{:?}", cert));
        
        let ptr : *mut x509_crt = (&mut chain).into();
        assert_ne!(ptr, ::core::ptr::null_mut());

        let cert : &mut Certificate = unsafe { UnsafeFrom::from(ptr).unwrap() };
        assert_eq!(c1_info, format!("{:?}", cert));
    }

    #[test]
    fn cert_send_sync() {
        assert!(crate::tests::TestTrait::<dyn Send, Certificate>::new().impls_trait(), "Certificate should be Send");
        assert!(crate::tests::TestTrait::<dyn Send, MbedtlsBox<Certificate>>::new().impls_trait(), "MbedtlsBox<Certificate> should be Send");
        assert!(crate::tests::TestTrait::<dyn Send, MbedtlsList<Certificate>>::new().impls_trait(), "MbedtlsList<Certificate> should be Send");
        assert!(crate::tests::TestTrait::<dyn Sync, Certificate>::new().impls_trait(), "Certificate should be Sync");
        assert!(crate::tests::TestTrait::<dyn Sync, MbedtlsBox<Certificate>>::new().impls_trait(), "MbedtlsBox<Certificate> should be Sync");
        assert!(crate::tests::TestTrait::<dyn Sync, MbedtlsList<Certificate>>::new().impls_trait(), "MbedtlsList<Certificate> should be Sync");
    }

    #[test]
    fn empty_crl_test() {
        const C_CERT: &'static str = concat!(include_str!("../../tests/data/certificate.crt"), "\0");
        const C_ROOT: &'static str = concat!(include_str!("../../tests/data/root.crt"), "\0");
        const C_CRL: &'static [u8] = include_bytes!("../../tests/data/root.empty.crl");

        let mut certs = MbedtlsList::new();
        certs.push(Certificate::from_pem(&C_CERT.as_bytes()).unwrap());
        let mut roots = MbedtlsList::new();
        roots.push(Certificate::from_pem(&C_ROOT.as_bytes()).unwrap());

        assert!(Certificate::verify(&certs, &roots, None, None).is_ok());

        let mut crl = Crl::new();
        crl.push_from_der(C_CRL).unwrap();
        assert!(Certificate::verify(&certs, &roots, Some(&mut crl), None).is_ok());
    }

    #[test]
    fn revoked_cert_crl_test() {
        const C_CERT: &'static str = concat!(include_str!("../../tests/data/certificate.crt"), "\0");
        const C_ROOT: &'static str = concat!(include_str!("../../tests/data/root.crt"), "\0");
        const C_CRL: &'static [u8] = include_bytes!("../../tests/data/root.revoked.crl");

        let mut certs = MbedtlsList::new();
        certs.push(Certificate::from_pem(&C_CERT.as_bytes()).unwrap());
        let mut roots = MbedtlsList::new();
        roots.push(Certificate::from_pem(&C_ROOT.as_bytes()).unwrap());

        let mut crl = Crl::new();
        crl.push_from_der(C_CRL).unwrap();

        let mut err = String::new();
        assert_eq!(
            Certificate::verify(&certs, &roots, Some(&mut crl), Some(&mut err)).unwrap_err(),
            Error::X509CertVerifyFailed
        );
        assert_eq!(err, "The certificate has been revoked (is on a CRL)\n");
    }
}
