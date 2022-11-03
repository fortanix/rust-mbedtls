/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use mbedtls_sys::*;

use core::ptr;
use core::convert::TryInto;
use crate::error::{Error, IntoResult, Result};
use crate::private::UnsafeFrom;
use crate::rng::Random;
use crate::hash::Type as MdType;

use byteorder::{BigEndian, ByteOrder};

pub(crate) mod dhparam;
mod ec;
mod rfc6979;

use self::rfc6979::Rfc6979Rng;
use crate::bignum::Mpi;
use crate::ecp::EcPoint;

#[cfg(feature = "dsa")]
pub mod dsa;

#[doc(inline)]
pub use self::ec::{EcGroupId, ECDSA_MAX_LEN};

#[doc(inline)]
pub use crate::ecp::EcGroup;

pub use dhparam::Dhm;

// SHA-256("Fortanix")[:4]
const CUSTOM_PK_TYPE: pk_type_t = 0x8b205408 as pk_type_t;

const RAW_RSA_DECRYPT : i32 = 1040451858;

define!(
    #[c_ty(pk_type_t)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    enum Type {
        None = PK_NONE,
        Rsa = PK_RSA,
        Eckey = PK_ECKEY,
        EckeyDh = PK_ECKEY_DH,
        // This type is never returned by the mbedTLS key parsing routines
        Ecdsa = PK_ECDSA,
        RsaAlt = PK_RSA_ALT,
        RsassaPss = PK_RSASSA_PSS,
        Opaque = PK_OPAQUE,
        Custom = CUSTOM_PK_TYPE,
    }
);

impl From<pk_type_t> for Type {
    fn from(inner: pk_type_t) -> Type {
        match inner {
            PK_NONE => Type::None,
            PK_RSA => Type::Rsa,
            PK_ECKEY => Type::Eckey,
            PK_ECKEY_DH => Type::EckeyDh,
            PK_ECDSA => Type::Ecdsa,
            PK_RSA_ALT => Type::RsaAlt,
            PK_RSASSA_PSS => Type::RsassaPss,
            PK_OPAQUE => Type::Opaque,
            CUSTOM_PK_TYPE => Type::Custom,
            _ => panic!("Invalid PK type"),
        }
    }
}

pub enum RsaPadding {
    Pkcs1V15,
    /// Use OAEP for encryption, or PSS for signing.
    Pkcs1V21 {
        /// The Mask Generating Function (MGF) to use.
        mgf: MdType,
    },
    None,
}

pub enum Options {
    Rsa { padding: RsaPadding },
}

// If this changes then certificate.rs unsafe code in public_key needs to also change.
define!(
    #[c_ty(pk_context)]
    #[repr(C)]
    struct Pk;
    const init: fn() -> Self = pk_init;
    const drop: fn(&mut Self) = pk_free;
    impl<'a> Into<ptr> {}
    impl<'a> UnsafeFrom<ptr> {}
);

// # Safety
//
// Thread safety analysis for Pk.
//
// A. Usage example of Pk.
//
// 1.1. Common use case is to to pass it as parameter to the SSL Config class.
// 1.2. SSL Config class is then used by multiple Context classes (one for each connection)
// 1.3. Context classes, handled by different threads will do calls towards Pk.
//
// Since this is a common use case for MbedTLS it should be thread safe if threading is enabled.
//
// B. Verifying thread safety.
//
// 1. Calls towards the specific Pk implementation are done via function pointers.
//
// - Example call towards Pk:
//    ../../../mbedtls-sys/vendor/library/ssl_srv.c:3707 - mbedtls_pk_decrypt( private_key, p, len, ...
// - This calls a generic function pointer via:
//    ../../../mbedtls-sys/vendor/crypto/library/pk.c:475 - return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
//
// 2. Pk implementation types.
//
// - The function pointers are defined via function:
//      ../../../mbedtls-sys/vendor/crypto/library/pk.c:115 - mbedtls_pk_info_from_type
// - They are as follows: mbedtls_rsa_info / mbedtls_eckey_info / mbedtls_ecdsa_info
// - These are defined in:
//       ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:196
//
// C. Checking types one by one.
//
// 1. RSA: mbedtls_rsa_info at ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:196
// This uses internal locks in: ../../../mbedtls-sys/vendor/crypto/library/rsa.c:718
//
// 2. ECKEY: mbedtls_eckey_info at ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:418
// This does not use internal locks but avoids interior mutability.
//
// Function checks one by one:
// - Only const access to context: eckey_check_pair, eckey_get_bitlen, eckey_can_do, eckey_check_pair
//
// - Const acccess / copies context to a stack based variable
//   eckey_verify_wrap, eckey_sign_wrap: ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:251
//       creates a stack ecdsa variable and uses ctx to initialize it.
//       ctx is passed as 'key', a const pointer to mbedtls_ecdsa_from_keypair( &ecdsa, ctx )
//           ../../../mbedtls-sys/vendor/crypto/library/ecdsa.c:819
//           int mbedtls_ecdsa_from_keypair( mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key )
//           key does not mutate.
//
// - Ignored due to not defined: eckey_verify_rs_wrap, eckey_sign_rs_wrap
//   (Undefined - MBEDTLS_ECP_RESTARTABLE - ../../../mbedtls-sys/build/config.rs:173)
//
// - Only used when creating/freeing - which is safe by design - eckey_alloc_wrap / eckey_free_wrap
//
// 3. ECDSA: mbedtls_ecdsa_info at ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:729
// This does not use internal locks but avoids interior mutability.
//
// - Const access / copies context to stack based variables:
//   ecdsa_verify_wrap: ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:544
//       This copies the public key on the stack - in buf[] and copies the group id and nbits.
//       That is done via: mbedtls_pk_write_pubkey( &p, buf, &key ) where key.private_pk_ctx = ctx;
//       And the key is a const parameter to mbedtls_pk_write_pubkey - ../../../mbedtls-sys/vendor/crypto/library/pkwrite.c:158
//
// - Const access with additional notes due to call stacks involved.
//
//   ecdsa_sign_wrap: ../../../mbedtls-sys/vendor/crypto/library/pk_wrap.c:657
//       mbedtls_ecdsa_write_signature ../../../mbedtls-sys/vendor/crypto/library/ecdsa.c:688
//           mbedtls_ecdsa_write_signature_restartable ../../../mbedtls-sys/vendor/crypto/library/ecdsa.c:640
//               MBEDTLS_ECDSA_DETERMINISTIC is not defined.
//               MBEDTLS_ECDSA_SIGN_ALT is not defined.
//               Passes grp to: ecdsa_sign_restartable: ../../../mbedtls-sys/vendor/crypto/library/ecdsa.c:253
//                    Const access to group - reads parameters, passed as const to mbedtls_ecp_gen_privkey,
//                    mbedtls_ecp_mul_restartable: ../../../mbedtls-sys/vendor/crypto/library/ecp.c:2351
//                        MBEDTLS_ECP_INTERNAL_ALT is not defined. (otherwise it might not be safe depending on ecp_init/ecp_free) ../../../mbedtls-sys/build/config.rs:131
//                        Passes as const to: mbedtls_ecp_check_privkey / mbedtls_ecp_check_pubkey / mbedtls_ecp_get_type( grp
//
// - Ignored due to not defined: ecdsa_verify_rs_wrap, ecdsa_sign_rs_wrap, ecdsa_rs_alloc, ecdsa_rs_free
//   (Undefined - MBEDTLS_ECP_RESTARTABLE - ../../../mbedtls-sys/build/config.rs:173)
//
// - Only const access to context: eckey_check_pair
//
// - Only used when creating/freeing - which is safe by design: ecdsa_alloc_wrap, ecdsa_free_wrap
//
unsafe impl Sync for Pk {}

impl Pk {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    ///
    /// When calling on PEM-encoded data, `key` must be NULL-terminated
    pub fn from_private_key<F: Random>(rng: &mut F, key: &[u8], password: Option<&[u8]>) -> Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            pk_parse_key(
                &mut ret.inner,
                key.as_ptr(),
                key.len(),
                password.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                password.map(<[_]>::len).unwrap_or(0),
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()?;
        };
        Ok(ret)
    }

    /// Takes both DER and PEM encoded SubjectPublicKeyInfo keys.
    ///
    /// When calling on PEM-encoded data, `key` must be NULL-terminated
    pub fn from_public_key(key: &[u8]) -> Result<Pk> {
        let mut ret = Self::init();
        unsafe { pk_parse_public_key(&mut ret.inner, key.as_ptr(), key.len()).into_result()? };
        Ok(ret)
    }

    pub fn generate_rsa<F: Random>(rng: &mut F, bits: u32, exponent: u32) -> Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            pk_setup(&mut ret.inner, pk_info_from_type(Type::Rsa.into())).into_result()?;
            rsa_gen_key(
                ret.inner.private_pk_ctx as *mut _,
                Some(F::call),
                rng.data_ptr(),
                bits,
                exponent as _,
            )
            .into_result()?;
        }
        Ok(ret)
    }

    pub fn generate_ec<F: Random, C: TryInto<EcGroup, Error = impl Into<Error>>>(rng: &mut F, curve: C) -> Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            let curve : EcGroup = curve.try_into().map_err(|e| e.into())?;
            pk_setup(&mut ret.inner, pk_info_from_type(Type::Eckey.into())).into_result()?;
            let ctx = ret.inner.private_pk_ctx as *mut ecp_keypair;
            (*ctx).private_grp = curve.clone().into_inner();
            ecp_gen_keypair(
                &mut (*ctx).private_grp,
                &mut (*ctx).private_d,
                &mut (*ctx).private_Q,
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()?;
        }
        Ok(ret)
    }

    pub fn private_from_ec_components<F: Random>(rng: &mut F, mut curve: EcGroup, private_key: Mpi) -> Result<Pk> {
        let mut ret = Self::init();
        let curve_generator = curve.generator()?;
        let public_point = curve_generator.mul(&mut curve, &private_key, rng)?;
        unsafe {
            pk_setup(&mut ret.inner, pk_info_from_type(Type::Eckey.into())).into_result()?;
            let ctx = ret.inner.private_pk_ctx as *mut ecp_keypair;
            (*ctx).private_grp = curve.into_inner();
            (*ctx).private_d = private_key.into_inner();
            (*ctx).private_Q = public_point.into_inner();
        }
        Ok(ret)
    }

    pub fn public_from_ec_components(curve: EcGroup, public_point: EcPoint) -> Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            pk_setup(&mut ret.inner, pk_info_from_type(Type::Eckey.into())).into_result()?;
            let ctx = ret.inner.private_pk_ctx as *mut ecp_keypair;
            (*ctx).private_grp = curve.into_inner();
            (*ctx).private_Q = public_point.into_inner();
        }
        Ok(ret)
    }

    /// Panics if the options are not valid for this key type.
    pub fn set_options(&mut self, options: Options) {
        unsafe {
            match (Type::from(pk_get_type(&self.inner)), options) {
                (Type::Rsa, Options::Rsa { padding })
                | (Type::RsassaPss, Options::Rsa { padding }) => {
                    let (padding, hash_id) = match padding {
                        RsaPadding::Pkcs1V15 => (RSA_PKCS_V15, 0),
                        RsaPadding::Pkcs1V21 { mgf } => (RSA_PKCS_V21, mgf.into()),
                        RsaPadding::None => {
                            let ctx = self.inner.private_pk_ctx as *mut rsa_context;
                            (*ctx).private_padding = RAW_RSA_DECRYPT; // denotes RawDecrypt padding being set
                            return;
                        }
                    };
                    rsa_set_padding(self.inner.private_pk_ctx as *mut rsa_context, padding, hash_id as _);
                }
                _ => panic!("Invalid options for this key type"),
            }
        }
    }

    pub fn can_do(&self, t: Type) -> bool {
        if unsafe { pk_can_do(&self.inner, t.into()) } == 0 {
            false
        } else {
            true
        }
    }

    pub fn check_pair<F: Random>(rng: &mut F, public: &Self, private: &Self) -> bool {
        unsafe { pk_check_pair(&public.inner, &private.inner,Some(F::call), rng.data_ptr()) }
            .into_result()
            .is_ok()
    }

    getter!(
        /// Key length in bits
        len() -> usize = fn pk_get_bitlen
    );
    getter!(pk_type() -> Type = fn pk_get_type);

    pub fn curve(&self) -> Result<EcGroupId> {
        match self.pk_type() {
            Type::Eckey | Type::EckeyDh | Type::Ecdsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        unsafe { Ok((*(self.inner.private_pk_ctx as *const ecp_keypair)).private_grp.id.into()) }
    }

    pub fn curve_oid(&self) -> Result<Vec<u64>> {
        match self.curve()? {
            EcGroupId::Bp256R1 => Ok(vec![1, 3, 36, 3, 3, 2, 8, 1, 1, 7]),
            EcGroupId::Bp384R1 => Ok(vec![1, 3, 36, 3, 3, 2, 8, 1, 1, 11]),
            EcGroupId::Bp512R1 => Ok(vec![1, 3, 36, 3, 3, 2, 8, 1, 1, 13]),
            EcGroupId::SecP192K1 => Ok(vec![1, 3, 132, 0, 31]),
            EcGroupId::SecP192R1 => Ok(vec![1, 2, 840, 10045, 3, 1, 1]),
            EcGroupId::SecP224K1 => Ok(vec![1, 3, 132, 0, 32]),
            EcGroupId::SecP224R1 => Ok(vec![1, 3, 132, 0, 33]),
            EcGroupId::SecP256K1 => Ok(vec![1, 3, 132, 0, 10]),
            EcGroupId::SecP256R1 => Ok(vec![1, 2, 840, 10045, 3, 1, 7]),
            EcGroupId::SecP384R1 => Ok(vec![1, 3, 132, 0, 34]),
            EcGroupId::SecP521R1 => Ok(vec![1, 3, 132, 0, 35]),
            _ => Err(Error::OidNotFound),
        }
    }

    pub fn ec_group(&self) -> Result<EcGroup> {
        match self.pk_type() {
            Type::Eckey | Type::EckeyDh | Type::Ecdsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        match self.curve()? {
            EcGroupId::None => {
                // custom curve, need to read params
                unsafe {
                    let ecp = self.inner.private_pk_ctx as *const ecp_keypair;
                    let p = Mpi::copy(&(*ecp).private_grp.P)?;
                    let a = Mpi::copy(&(*ecp).private_grp.A)?;
                    let b = Mpi::copy(&(*ecp).private_grp.B)?;
                    let n = Mpi::copy(&(*ecp).private_grp.N)?;
                    let g_x = Mpi::copy(&(*ecp).private_grp.G.private_X)?;
                    let g_y = Mpi::copy(&(*ecp).private_grp.G.private_Y)?;
                    EcGroup::from_parameters(p, a, b, g_x, g_y, n)
                }
            }

            curve_id => EcGroup::new(curve_id),
        }
    }

    pub fn ec_public(&self) -> Result<EcPoint> {
        match self.pk_type() {
            Type::Eckey | Type::EckeyDh | Type::Ecdsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let q = &unsafe { (*(self.inner.private_pk_ctx as *const ecp_keypair)).private_Q };
        EcPoint::copy(q)
    }

    pub fn ec_private(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Eckey | Type::EckeyDh | Type::Ecdsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let d = &unsafe { (*(self.inner.private_pk_ctx as *const ecp_keypair)).private_d };
        Mpi::copy(d)
    }

    pub fn rsa_public_modulus(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut n = Mpi::new(0)?;

        unsafe {
            rsa_export(
                self.inner.private_pk_ctx as *const rsa_context,
                n.handle_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(n)
    }

    pub fn rsa_private_prime1(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut p = Mpi::new(0)?;

        unsafe {
            rsa_export(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                p.handle_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(p)
    }

    pub fn rsa_private_prime2(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut q = Mpi::new(0)?;

        unsafe {
            rsa_export(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                ptr::null_mut(),
                q.handle_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(q)
    }

    pub fn rsa_private_exponent(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut d = Mpi::new(0)?;

        unsafe {
            rsa_export(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                d.handle_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(d)
    }

    pub fn rsa_crt_dp(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut dp = Mpi::new(0)?;

        unsafe {
            rsa_export_crt(
                self.inner.private_pk_ctx as *const rsa_context,
                dp.handle_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(dp)
    }

    pub fn rsa_crt_dq(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut dq = Mpi::new(0)?;

        unsafe {
            rsa_export_crt(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                dq.handle_mut(),
                ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(dq)
    }

    pub fn rsa_crt_qp(&self) -> Result<Mpi> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut qp = Mpi::new(0)?;

        unsafe {
            rsa_export_crt(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                ptr::null_mut(),
                qp.handle_mut(),
            )
            .into_result()?;
        }

        Ok(qp)
    }

    pub fn rsa_public_exponent(&self) -> Result<u32> {
        match self.pk_type() {
            Type::Rsa => {}
            _ => return Err(Error::PkTypeMismatch),
        }

        let mut e: [u8; 4] = [0, 0, 0, 0];
        unsafe {
            rsa_export_raw(
                self.inner.private_pk_ctx as *const rsa_context,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                e.as_mut_ptr(),
                e.len(),
            )
            .into_result()?;
        }
        Ok(BigEndian::read_u32(&e))
    }

    pub fn name(&self) -> Result<&str> {
        let s = unsafe { crate::private::cstr_to_slice(pk_get_name(&self.inner)) };
        Ok(::core::str::from_utf8(s)?)
    }

    pub fn decrypt<F: Random>(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
        rng: &mut F,
    ) -> Result<usize> {
        if self.pk_type() == Type::Rsa {
            let ctx = self.inner.private_pk_ctx as *mut rsa_context;
            if unsafe { (*ctx).private_padding  == RAW_RSA_DECRYPT } {
                let olen = self.len() / 8;
                if plain.len() < olen {
                    return Err(Error::RsaOutputTooLarge);
                }

                unsafe {
                    rsa_private(
                        ctx,
                        Some(F::call),
                        rng.data_ptr(),
                        cipher.as_ptr(),
                        plain.as_mut_ptr()
                    ).into_result()?;
                };
                return Ok(olen);
            }
        }

        let mut ret = 0usize;
        unsafe {
            pk_decrypt(
                &mut self.inner,
                cipher.as_ptr(),
                cipher.len(),
                plain.as_mut_ptr(),
                &mut ret,
                plain.len(),
                Some(F::call),
                rng.data_ptr(),
            ).into_result()?;
        };
        Ok(ret)
    }

    /// Decrypt using a custom label.
    ///
    /// This function may only be called on an RSA key with its padding set to RSA_PKCS_V21.
    pub fn decrypt_with_label<F: Random>(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
        rng: &mut F,
        label: &[u8],
    ) -> Result<usize> {
        if self.pk_type() != Type::Rsa {
            return Err(Error::PkTypeMismatch);
        }
        let ctx = self.inner.private_pk_ctx as *mut rsa_context;
        if unsafe { (*ctx).private_padding != RSA_PKCS_V21 } {
            return Err(Error::RsaInvalidPadding);
        }

        let mut ret = 0usize;
        unsafe {
            rsa_rsaes_oaep_decrypt(
                ctx,
                Some(F::call),
                rng.data_ptr(),
                label.as_ptr(),
                label.len(),
                &mut ret,
                cipher.as_ptr(),
                plain.as_mut_ptr(),
                plain.len(),
            ).into_result()?;
        }
        Ok(ret)
    }

    pub fn encrypt<F: Random>(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
        rng: &mut F,
    ) -> Result<usize> {
        let mut ret = 0usize;
        unsafe {
            pk_encrypt(
                &mut self.inner,
                plain.as_ptr(),
                plain.len(),
                cipher.as_mut_ptr(),
                &mut ret,
                cipher.len(),
                Some(F::call),
                rng.data_ptr(),
            ).into_result()?;
        };
        Ok(ret)
    }

    /// Encrypt using a custom label.
    ///
    /// This function may only be called on an RSA key with its padding set to RSA_PKCS_V21.
    pub fn encrypt_with_label<F: Random>(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
        rng: &mut F,
        label: &[u8],
    ) -> Result<usize> {
        if self.pk_type() != Type::Rsa {
            return Err(Error::PkTypeMismatch);
        }
        let ctx = self.inner.private_pk_ctx as *mut rsa_context;
        if unsafe { (*ctx).private_padding != RSA_PKCS_V21 } {
            return Err(Error::RsaInvalidPadding);
        }
        let olen = self.len() / 8;
        if cipher.len() < olen {
            return Err(Error::RsaOutputTooLarge);
        }

        unsafe {
            rsa_rsaes_oaep_encrypt(
                ctx,
                Some(F::call),
                rng.data_ptr(),
                label.as_ptr(),
                label.len(),
                plain.len(),
                plain.as_ptr(),
                cipher.as_mut_ptr()
            ).into_result()?;
        }
        Ok(olen)
    }

    /// Sign the hash `hash` of type `md`, placing the signature in `sig`. `rng` must be a
    /// cryptographically secure RNG.
    ///
    /// For RSA signatures, the length of `sig` must be greater than or equal to the RSA
    /// modulus length, otherwise `sign()` fails with `Error::PkSigLenMismatch`.
    ///
    /// For EC signatures, the length of `sig` must be greater than or equal to `ECDSA_MAX_LEN`,
    /// otherwise `sign()` fails with `Error::PkSigLenMismatch`.
    ///
    /// On success, returns the actual number of bytes written to `sig`.
    pub fn sign<F: Random>(
        &mut self,
        md: MdType,
        hash: &[u8],
        sig: &mut [u8],
        rng: &mut F,
    ) -> Result<usize> {
        // If hash or sig are allowed with size 0 (&[]) then mbedtls will attempt to auto-detect size and cause an invalid write.
        if hash.len() == 0 || sig.len() == 0 {
            return Err(Error::PkBadInputData)
        }

        match self.pk_type() {
            Type::Rsa | Type::RsaAlt | Type::RsassaPss => {
                if sig.len() < (self.len() / 8) {
                    return Err(Error::PkSigLenMismatch);
                }
            }
            Type::Eckey | Type::Ecdsa => {
                if sig.len() < ECDSA_MAX_LEN {
                    return Err(Error::PkSigLenMismatch);
                }
            }
            _ => return Err(Error::PkSigLenMismatch),
        }
        let mut ret = 0usize;
        unsafe {
            pk_sign(
                &mut self.inner,
                md.into(),
                hash.as_ptr(),
                hash.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut ret,
                Some(F::call),
                rng.data_ptr(),
            ).into_result()?;
        };
        Ok(ret)
    }

    pub fn sign_deterministic<F: Random>(
        &mut self,
        md: MdType,
        hash: &[u8],
        sig: &mut [u8],
        rng: &mut F,
    ) -> Result<usize> {
        // If hash or sig are allowed with size 0 (&[]) then mbedtls will attempt to auto-detect size and cause an invalid write.
        if hash.len() == 0 || sig.len() == 0 {
            return Err(Error::PkBadInputData)
        }

        use crate::rng::RngCallbackMut;

        if self.pk_type() == Type::Ecdsa || self.pk_type() == Type::Eckey {
            if sig.len() < ECDSA_MAX_LEN {
                return Err(Error::PkSigLenMismatch);
            }

            // RFC 6979 signature scheme
            let q = EcGroup::new(self.curve()?)?.order()?;
            let x = self.ec_private()?;

            let mut random_seed = [0u8; 64];
            rng.random(&mut random_seed)?;

            let mut rng = Rfc6979Rng::new(md, &q, &x, hash, &random_seed)?;

            let mut ret = 0usize;
            unsafe {
                pk_sign(
                    &mut self.inner,
                    md.into(),
                    hash.as_ptr(),
                    hash.len(),
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut ret,
                    Some(Rfc6979Rng::call_mut),
                    rng.data_ptr_mut(),
                ).into_result()?;
            };
            Ok(ret)
        } else if self.pk_type() == Type::Rsa {
            // Reject sign_deterministic being use for PSS
            if unsafe { (*(self.inner.private_pk_ctx as *mut rsa_context)).private_padding } != RSA_PKCS_V15 {
                return Err(Error::PkInvalidAlg);
            }

            // This is a PKCSv1.5 signature which is already deterministic; just pass it to sign
            return self.sign(md, hash, sig, rng);
        } else {
            // Some non-deterministic scheme
            return Err(Error::PkInvalidAlg);
        }
    }

    pub fn verify(&mut self, md: MdType, hash: &[u8], sig: &[u8]) -> Result<()> {
        // If hash or sig are allowed with size 0 (&[]) then mbedtls will attempt to auto-detect size and cause an invalid write.
        if hash.len() == 0 || sig.len() == 0 {
            return Err(Error::PkBadInputData)
        }

        unsafe {
            pk_verify(
                &mut self.inner,
                md.into(),
                hash.as_ptr(),
                hash.len(),
                sig.as_ptr(),
                sig.len(),
            )
            .into_result()
            .map(|_| ())
        }
    }

    /// Agree on a shared secret with another public key.
    pub fn agree<F: Random>(
        &mut self,
        other: &Pk,
        shared: &mut [u8],
        rng: &mut F,
    ) -> Result<usize> {
        match (self.pk_type(), other.pk_type()) {
            (Type::Eckey, Type::Eckey)
            | (Type::EckeyDh, Type::Eckey)
            | (Type::Eckey, Type::EckeyDh)
            | (Type::EckeyDh, Type::EckeyDh) => unsafe {
                let mut ecdh = ec::Ecdh::from_keys(
                    UnsafeFrom::from(self.inner.private_pk_ctx as *const _).unwrap(),
                    UnsafeFrom::from(other.inner.private_pk_ctx as *const _).unwrap(),
                )?;
                ecdh.calc_secret(shared, rng)
            },
            _ => return Err(Error::PkTypeMismatch),
        }
    }

    pub fn write_private_der<'buf>(&mut self, buf: &'buf mut [u8]) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_key_der(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_private_der_vec(&mut self) -> Result<Vec<u8>> {
        crate::private::alloc_vec_repeat(
            |buf, size| unsafe { pk_write_key_der(&mut self.inner, buf, size) },
            true,
        )
    }

    pub fn write_private_pem<'buf>(&mut self, buf: &'buf mut [u8]) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_key_pem(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_private_pem_string(&mut self) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            match pk_write_key_pem(&mut self.inner, buf as _, size) {
                0 => crate::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }

    pub fn write_public_der<'buf>(&mut self, buf: &'buf mut [u8]) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_pubkey_der(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_public_der_vec(&mut self) -> Result<Vec<u8>> {
        crate::private::alloc_vec_repeat(
            |buf, size| unsafe { pk_write_pubkey_der(&mut self.inner, buf, size) },
            true,
        )
    }

    pub fn write_public_pem<'buf>(&mut self, buf: &'buf mut [u8]) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_pubkey_pem(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_public_pem_string(&mut self) -> Result<String> {
        crate::private::alloc_string_repeat(|buf, size| unsafe {
            match pk_write_pubkey_pem(&mut self.inner, buf as _, size) {
                0 => crate::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }
}

// pk_verify_ext
//
// pk_info_from_type
// pk_setup
// pk_setup_rsa_alt
//
// pk_debug
// pk_parse_keyfile
// pk_parse_public_keyfile
// pk_write_key_der
// pk_write_key_pem
// pk_write_pubkey_der
// pk_write_pubkey_pem
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Type, MdInfo};

    // This is test data that must match library output *exactly*
    const TEST_PEM: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh1aoz6wFwVHaCVDISSy+dZ8rOsJmfYBCrgzUjX+VNb2RwdT8
xv5fF0j0IXq+fKBShdZA+WGEQd6BMU0fqc2o7ACLvPWbvdKrLcwWpnL/UpFV8PxJ
yLemR8CBkGYcN2EJHhRhZcAGMBKwR1lI+ymOPJz4+nyDWVh9ttrvkKZU9b59zDkP
ET6PDJb5x9+fd41laQVOLvwlF4Xrl0b0DakXF3BVYpJIJ+b51QnMnwQ2xHVybFlZ
ONBwv1h52Xy7chvx79zPXzxZFbEc0phIhRqenv0/6/8HxpqqctSs9HHUn5A+4d/o
955ki8ZB1Nl5EuY+S59HzdsnQXR+OZxt3PxjTQIDAQABAoIBAANfW3UaPdfOTFqh
S5jXNbUhFgp3sa2ufaWMraHvQYPwM9Vo6KSIXGleIZV7/jVo0x6BVry1e2ICmMGR
FjWSIqAkPuVp36DD+9QGU+zVBan9SSgTD5SFh+4dzNWfOVRVSSJu+c13hKG70e5/
5KLKDvmKXSye/Ftg8VuysWmS6bxolGm86b+tltQ95V2qgim41MpaOUzilf1sDc5A
3hnorZvxH+kbMSGTRBdlPX54dux0SlT+o7sh9ig2sPJKkevnHeWd6nEeyeVYzP05
vH5yXirYb1CttPb5tqLcNCKRgawR5ByMMycn8bRSHScxyCLKco++JWL7L8hmcFTM
qFqCa9kCgYEAunw/Qofipch+bcMDsNmd6d9s9l1bBpXkP1ARQohuoVpsJITg+CH6
Dm3tWHnawwCxuQEUZ1/2cqZtrDBukgC90HK0H5j6b8FfyQ0mS3OOnqBHnhV66AXM
Hzlin1Vgaqwuhooy/CfOAyqpMqAfCgCAscxs6EOMteYrY+Xy7Ou02fMCgYEAucme
nNMsSElhsQwW7xpz8rr4k3THKSoetg2pbaUwXR4XDz/J1XWCIkSo8RuN1hA+z6+a
GzJa7CozmaM1j7aGo91U/LN/aNZ9etEbDOO+WCU/K0uTFtVAwgivRqETMARzEvuy
r1M2amUUDM5pX8Jk/Q19cGXQdyJdpShqp8Y93b8CgYEAhukkCsmrmiv16wpOPT7y
EyPj/EeFdroxqewO0IdLIcf8vF61Mk3CTXYRYxSkwrZZ3HF/hVnTPRZR+WQAWffX
WlnhHYragsbuuNCeh69N2kwyA5eelwS6q0wkoQhu/D0cW5DXWbyiOYA/b7SPP/kl
IXu2vkFAJsghU+AjYmsTJykCgYBtuzvHfKKG/3CH1ZAmIQWis/Plg++tzIbfGCqd
7BcoqIEOLKrVPNZjzxHJdnDLokS2/gyTS6aQHkzjzZXxD+luF2f+6TWzghwS0jab
4lemUDmDJNv3fHUHJYIAwVpH3hjpeWgMTaWyKYkyFyf9ux9SpwkTvc7mzpFo3vo/
pcMcmQKBgCVZpfRJxJ1pc4v0M2pxF3zsyDo3CbvhO7ZjOwYyNa5A+p65BsGbOjuR
2v6GLNvYtgqM+FXqTyqz2RkyoKIOqXyOWdSDPHaP2mu5A0xaTom6H7F8PuNFIm4F
iy6KC991zzvaWY/Ys+q/84Afqa+0qJKQnPuy/7F5GkVdQA/lfbhi
-----END RSA PRIVATE KEY-----
\0";

    const TEST_DER: &'static [u8] = &[
        0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0x8d, 0x76, 0xa1,
        0x2e, 0xb6, 0xc0, 0xe5, 0x1e, 0x1a, 0x06, 0x74, 0x13, 0x57, 0x6a, 0xc2, 0x6c, 0x02, 0x9d,
        0x82, 0x91, 0x5b, 0xb0, 0xe5, 0xa9, 0x7f, 0xe0, 0x6d, 0x3f, 0xc0, 0x94, 0x88, 0x8e, 0x72,
        0xd4, 0x4a, 0xc1, 0xf5, 0x54, 0x71, 0x63, 0x10, 0xaa, 0xef, 0x9d, 0xa5, 0x1a, 0xdc, 0x00,
        0x82, 0x2d, 0xea, 0x5f, 0x5b, 0xe8, 0x73, 0x6e, 0x03, 0xf8, 0x07, 0x90, 0x8c, 0xd5, 0x52,
        0xf5, 0x6d, 0xfc, 0x4d, 0xe5, 0x6a, 0x87, 0x5a, 0x85, 0xf7, 0x34, 0x85, 0x9a, 0x19, 0x3a,
        0x74, 0x46, 0x1e, 0xcb, 0x30, 0x77, 0x8d, 0x68, 0x8a, 0xb8, 0xfd, 0x6e, 0xbc, 0xee, 0xd2,
        0xd0, 0xb3, 0xd0, 0x1c, 0x44, 0x29, 0xd0, 0xd6, 0x91, 0xb5, 0xa8, 0xc1, 0xe3, 0x88, 0x64,
        0x40, 0x16, 0x31, 0x6c, 0xdc, 0x4b, 0xba, 0x69, 0xc3, 0xcd, 0x8d, 0x4a, 0xd8, 0x7d, 0xf4,
        0xa7, 0xe2, 0xe8, 0xc5, 0x01, 0x6f, 0xcc, 0x91, 0x22, 0x81, 0x52, 0x83, 0x11, 0x28, 0xb3,
        0x97, 0x1d, 0x57, 0xa2, 0x2a, 0x01, 0x77, 0x65, 0x87, 0x3e, 0xdc, 0x6c, 0x7f, 0x0a, 0xca,
        0x95, 0x04, 0x6a, 0x4e, 0x47, 0xa4, 0xfb, 0xa1, 0x42, 0x19, 0x0f, 0x80, 0x14, 0xed, 0xf9,
        0x4a, 0x42, 0x9c, 0x6f, 0xef, 0x0f, 0x82, 0x51, 0xbb, 0x46, 0x66, 0xc6, 0xfd, 0xd9, 0x01,
        0x93, 0x6d, 0xda, 0x36, 0xc7, 0x58, 0x37, 0x4b, 0xa7, 0xdb, 0xbd, 0xb2, 0x6f, 0x5b, 0x33,
        0x4b, 0x78, 0x70, 0x7e, 0xe8, 0x02, 0xdd, 0x5f, 0xa4, 0x2f, 0xea, 0x3c, 0x6b, 0xfb, 0x51,
        0xe1, 0x19, 0x21, 0x9f, 0x52, 0xd6, 0x29, 0x53, 0x09, 0x98, 0xbc, 0x3e, 0x3b, 0xb3, 0xdc,
        0x25, 0x13, 0x36, 0x1b, 0x24, 0xf4, 0x33, 0xdd, 0xdf, 0xa8, 0xd6, 0xe8, 0x97, 0x11, 0x2f,
        0x9a, 0x81, 0xc1, 0xb6, 0xf1, 0x7b, 0xa5, 0xa4, 0x2c, 0xda, 0x41, 0xb6, 0x11, 0x02, 0x03,
        0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x38, 0x98, 0xb9, 0xab, 0xe2, 0xda, 0x11, 0xd0,
        0x95, 0x40, 0xf7, 0xb7, 0xb5, 0x45, 0xb5, 0x3b, 0x59, 0x60, 0x83, 0x18, 0x7c, 0xc2, 0xad,
        0x5f, 0xbf, 0x15, 0x9f, 0x1f, 0xde, 0x80, 0x8e, 0x91, 0xcf, 0x47, 0x38, 0x11, 0x99, 0x81,
        0x8b, 0x4b, 0xc3, 0x23, 0x60, 0x72, 0x85, 0xd7, 0xd5, 0x25, 0x2e, 0xf0, 0x07, 0xd0, 0xd7,
        0x08, 0x8d, 0x05, 0xfa, 0xf8, 0x84, 0xae, 0x44, 0x6a, 0x24, 0xa2, 0xa4, 0xba, 0x48, 0xbf,
        0xfc, 0x7a, 0xe2, 0xb0, 0xae, 0x52, 0x89, 0x11, 0x39, 0xfe, 0xb4, 0xfe, 0x48, 0xdb, 0xaa,
        0x2c, 0x6a, 0x9a, 0xe4, 0xc5, 0x56, 0x3f, 0xb3, 0xbf, 0x29, 0x00, 0xee, 0xaf, 0xd8, 0x5f,
        0x3d, 0x0b, 0x9c, 0x8c, 0xf7, 0x4c, 0xe9, 0x25, 0x8b, 0x2f, 0xf0, 0xa3, 0xf0, 0x6a, 0x49,
        0x48, 0xd2, 0xef, 0xf5, 0xb2, 0x8b, 0x50, 0xe2, 0x84, 0xa2, 0x19, 0x79, 0x22, 0xff, 0x8e,
        0x16, 0xbe, 0x00, 0x70, 0xc4, 0x6d, 0xd0, 0x29, 0x54, 0x28, 0x99, 0x97, 0x84, 0xc9, 0xaf,
        0xd8, 0xb6, 0xb1, 0x44, 0x6d, 0x4a, 0x74, 0x82, 0x4e, 0xde, 0x44, 0x1c, 0x47, 0x11, 0x52,
        0x86, 0x48, 0xd7, 0x78, 0x52, 0xa9, 0x98, 0x20, 0x9d, 0x83, 0x39, 0x3d, 0xe5, 0xd6, 0xed,
        0x94, 0x6a, 0x67, 0xd0, 0x65, 0x23, 0xf6, 0xdd, 0xe1, 0xe3, 0xed, 0xe9, 0x6b, 0x85, 0xcb,
        0x91, 0x0b, 0xcd, 0xc4, 0x6b, 0xe4, 0x90, 0xd4, 0xeb, 0x7b, 0x80, 0x0b, 0x67, 0x9d, 0xb5,
        0x37, 0x0b, 0x83, 0x7d, 0x79, 0x45, 0x6b, 0x60, 0x7d, 0x6f, 0xe3, 0xe0, 0x5e, 0x92, 0xf6,
        0x13, 0x67, 0xd2, 0xd4, 0xdc, 0x43, 0x5f, 0xd8, 0xee, 0xf5, 0x28, 0x05, 0x64, 0x78, 0x6a,
        0x6f, 0xaf, 0xef, 0x64, 0x52, 0x93, 0x70, 0x4f, 0x9a, 0xab, 0xce, 0x4a, 0x51, 0x63, 0x2a,
        0xf1, 0x33, 0xfd, 0xd8, 0x1e, 0xf9, 0xef, 0xf1, 0x02, 0x81, 0x81, 0x00, 0xcf, 0xa7, 0x89,
        0x75, 0xdd, 0x09, 0x66, 0x8b, 0x4e, 0xda, 0x52, 0x38, 0x4a, 0xc3, 0x7c, 0xca, 0x90, 0x68,
        0x4a, 0xbb, 0x78, 0x14, 0xc1, 0x83, 0x24, 0xb2, 0x2e, 0x39, 0x20, 0x8a, 0x00, 0x97, 0x8d,
        0xf3, 0x21, 0x5a, 0xad, 0x03, 0xc7, 0xb2, 0xe9, 0x17, 0x10, 0x85, 0x63, 0x23, 0xe3, 0xc9,
        0x73, 0x91, 0xa8, 0x5a, 0x8d, 0xb6, 0x40, 0x0f, 0x98, 0xb8, 0x2a, 0x8f, 0x7e, 0x59, 0x80,
        0x8a, 0xee, 0xb9, 0xe9, 0x9b, 0x2e, 0x83, 0xd4, 0x85, 0xc1, 0xdc, 0x1e, 0xc9, 0x44, 0x48,
        0x2a, 0x13, 0x06, 0x09, 0x02, 0x3e, 0x3f, 0xfb, 0xf2, 0xe8, 0x1a, 0x2d, 0xec, 0x40, 0xea,
        0x0e, 0x2b, 0x7f, 0xf3, 0x79, 0xdc, 0x11, 0x3b, 0x0d, 0xb8, 0x3f, 0x4f, 0x06, 0x02, 0x17,
        0x7c, 0x79, 0xa7, 0x36, 0x56, 0xef, 0xcd, 0x1a, 0x41, 0x00, 0x2c, 0xe8, 0x2e, 0x55, 0x9b,
        0x10, 0xea, 0x19, 0xb2, 0xe3, 0x02, 0x81, 0x81, 0x00, 0xae, 0x66, 0x06, 0x29, 0xcd, 0x44,
        0x6b, 0x4d, 0xb0, 0x1e, 0xba, 0xb8, 0x4f, 0x5e, 0x06, 0xaa, 0x02, 0x58, 0xc9, 0xb5, 0x46,
        0x68, 0xe0, 0xaf, 0x48, 0x48, 0x82, 0x45, 0xd2, 0x9c, 0xa5, 0x2d, 0x9d, 0xe6, 0x7a, 0x16,
        0xe6, 0xba, 0x8c, 0xe9, 0x2b, 0x61, 0xaf, 0x40, 0x8c, 0xab, 0x38, 0x17, 0x4e, 0xe1, 0xf7,
        0x0d, 0x52, 0xb8, 0x78, 0xcc, 0x4d, 0xcb, 0xdc, 0xe4, 0xb7, 0x4f, 0x41, 0xdf, 0xde, 0x34,
        0x20, 0x5f, 0xac, 0x45, 0x6f, 0xed, 0xcd, 0xc0, 0x4d, 0x88, 0x7a, 0xf4, 0xc9, 0x8a, 0xa4,
        0xf7, 0x40, 0x41, 0x4d, 0xb6, 0x98, 0x1f, 0x2a, 0x42, 0x42, 0x62, 0xd2, 0xb1, 0xef, 0x84,
        0x94, 0x87, 0x09, 0xfe, 0xf1, 0xba, 0xb2, 0xb8, 0x6c, 0x99, 0xb2, 0x77, 0xa6, 0xd8, 0x91,
        0x07, 0xb5, 0xd9, 0x7d, 0xe8, 0x59, 0xc0, 0xfa, 0x5a, 0x55, 0xf4, 0x3a, 0x82, 0xf4, 0x78,
        0xa1, 0x7b, 0x02, 0x81, 0x80, 0x3f, 0x6e, 0xfa, 0x7a, 0xda, 0xce, 0xe8, 0x58, 0x5d, 0xfa,
        0x2b, 0x6b, 0xae, 0xcb, 0x10, 0xf0, 0x00, 0x35, 0x1b, 0xbf, 0x30, 0xeb, 0x86, 0x41, 0xbd,
        0x90, 0x00, 0xb6, 0xca, 0xcd, 0xdd, 0x68, 0x6e, 0xa0, 0x7a, 0xeb, 0xec, 0x36, 0x5f, 0x66,
        0xb3, 0xf5, 0xab, 0xc2, 0x53, 0x8a, 0xbf, 0x26, 0xe6, 0xfa, 0xf3, 0xe6, 0xd5, 0xab, 0x7a,
        0xde, 0x48, 0xd4, 0xd9, 0x8b, 0x84, 0x19, 0x6b, 0x3f, 0x05, 0xb6, 0x1d, 0x3a, 0x9e, 0x76,
        0xff, 0x10, 0xed, 0x2b, 0x84, 0xec, 0x0e, 0xc3, 0xcc, 0xb6, 0x8a, 0xfd, 0x6d, 0x85, 0xfe,
        0x9d, 0xc4, 0x92, 0x4a, 0x8d, 0x04, 0xc2, 0xbf, 0xbd, 0x1c, 0x64, 0xb5, 0xc7, 0xe0, 0x06,
        0x13, 0x78, 0x19, 0x74, 0x9d, 0x7b, 0x44, 0x60, 0x50, 0x52, 0x09, 0x56, 0x7c, 0x30, 0x3d,
        0x03, 0x6c, 0x1f, 0xd5, 0x98, 0x07, 0xaf, 0x76, 0xf3, 0x2f, 0xd0, 0x31, 0xe9, 0x02, 0x81,
        0x81, 0x00, 0xa6, 0x61, 0x77, 0x67, 0xd2, 0x09, 0x80, 0x45, 0xb1, 0xcc, 0xdf, 0x5e, 0x8f,
        0x79, 0xa8, 0xe9, 0xf1, 0x2b, 0x3b, 0xe4, 0xd1, 0xb3, 0xa5, 0x08, 0x14, 0xf1, 0xf8, 0x37,
        0x1c, 0xe3, 0x8d, 0x42, 0xa3, 0xee, 0x0a, 0x74, 0x66, 0xd3, 0x7b, 0x33, 0xc8, 0xcb, 0x7d,
        0x23, 0x1c, 0x11, 0x0d, 0x86, 0x4f, 0x1f, 0x8d, 0x4f, 0x0c, 0xa8, 0x29, 0xb6, 0xe0, 0x51,
        0xaa, 0x00, 0x1a, 0x52, 0x67, 0x0a, 0x69, 0x37, 0x59, 0xdb, 0x6c, 0xc3, 0x22, 0x31, 0xc1,
        0xa5, 0xc1, 0x52, 0x7f, 0xdb, 0xa1, 0x9b, 0xc0, 0x1e, 0x93, 0x12, 0xba, 0x4d, 0x85, 0x7b,
        0xd6, 0x19, 0x38, 0xb4, 0x87, 0x46, 0x72, 0xb8, 0x0d, 0xeb, 0x77, 0x41, 0xde, 0xe4, 0xbb,
        0x34, 0xef, 0x87, 0x02, 0x98, 0xdc, 0x78, 0xa8, 0x84, 0xae, 0x9d, 0x3c, 0x5d, 0xbb, 0xa3,
        0x3c, 0x35, 0x8a, 0xe3, 0x62, 0x1f, 0x25, 0x95, 0x20, 0x99, 0x02, 0x81, 0x80, 0x5b, 0xfb,
        0x99, 0x65, 0xaa, 0x0d, 0x55, 0xf5, 0x66, 0x27, 0x95, 0xc8, 0xb2, 0x68, 0x7f, 0x8b, 0xd3,
        0x26, 0xd1, 0x51, 0x68, 0xe3, 0x5f, 0x84, 0x1b, 0x13, 0xbf, 0xec, 0xb4, 0x92, 0x09, 0xa8,
        0x0c, 0xac, 0x5f, 0x99, 0x3a, 0xd5, 0xda, 0xdd, 0xee, 0xba, 0x1c, 0xce, 0x92, 0x7c, 0x54,
        0xd4, 0xf8, 0x6a, 0xc3, 0xb3, 0x07, 0xea, 0xce, 0x18, 0xad, 0x8e, 0x26, 0x5e, 0x54, 0xa1,
        0x87, 0x77, 0x6a, 0x7b, 0x23, 0x2e, 0x76, 0xb6, 0x3a, 0xe7, 0xd9, 0x67, 0x0d, 0x7e, 0x19,
        0xd9, 0x6e, 0x2c, 0xe0, 0x00, 0xd6, 0x8e, 0xd2, 0x5a, 0xc9, 0x59, 0x44, 0x58, 0xd8, 0x73,
        0x15, 0x0f, 0x17, 0x63, 0x3e, 0xef, 0x74, 0x2f, 0xfe, 0xbd, 0x50, 0x07, 0x5f, 0x7d, 0x15,
        0x23, 0xab, 0xc2, 0x77, 0x6d, 0xc9, 0x3d, 0x08, 0x1a, 0x88, 0xdd, 0x45, 0x26, 0xd9, 0x2d,
        0xe9, 0xde, 0xb9, 0x58, 0x36, 0x5f,
    ];

    #[test]
    fn generate_rsa() {
        let mut pk =
            Pk::generate_rsa(&mut crate::test_support::rand::test_rng(), 2048, 0x10001).unwrap();
        let generated = pk.write_private_pem_string().unwrap();
        assert_eq!(0x10001, pk.rsa_public_exponent().unwrap());
        assert_eq!(generated, TEST_PEM[..TEST_PEM.len() - 1]);
    }

    #[test]
    fn generate_ec_curve25519() {
        let _generated =
            Pk::generate_ec(&mut crate::test_support::rand::test_rng(), EcGroupId::Curve25519).unwrap();
        // mbedtls does not have an OID for Curve25519, so can't write it as PEM
    }

    #[test]
    fn generate_ec_secp192r1() {
        let _generated =
            Pk::generate_ec(&mut crate::test_support::rand::test_rng(), EcGroupId::SecP192R1)
                .unwrap()
                .write_private_pem_string()
                .unwrap();
    }

    #[test]
    fn generate_ec_secp256r1() {
        let mut key1 =
            Pk::generate_ec(&mut crate::test_support::rand::test_rng(), EcGroupId::SecP256R1).unwrap();
        let pem1 = key1.write_private_pem_string().unwrap();

        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1).unwrap();
        let mut key2 =
            Pk::generate_ec(&mut crate::test_support::rand::test_rng(), secp256r1.clone())
                .unwrap();
        let pem2 = key2.write_private_pem_string().unwrap();

        assert_eq!(pem1, pem2);

        let mut key_from_components =
            Pk::private_from_ec_components(&mut crate::test_support::rand::test_rng(), secp256r1.clone(), key1.ec_private().unwrap()).unwrap();
        let pem3 = key_from_components.write_private_pem_string().unwrap();

        assert_eq!(pem3, pem2);

        let mut pub1 = Pk::from_public_key(&key1.write_public_der_vec().unwrap()).unwrap();
        let mut pub2 =
            Pk::public_from_ec_components(secp256r1.clone(), key1.ec_public().unwrap()).unwrap();

        assert_eq!(
            pub1.write_public_pem_string().unwrap(),
            pub2.write_public_pem_string().unwrap()
        );
    }

    #[test]
    fn generate_ec_secp256k1() {
        let _generated =
            Pk::generate_ec(&mut crate::test_support::rand::test_rng(), EcGroupId::SecP256K1)
                .unwrap()
                .write_private_pem_string()
                .unwrap();
    }

    #[test]
    fn parse_write_pem() {
        let parsed = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_PEM.as_bytes(), None)
            .unwrap()
            .write_private_pem_string()
            .unwrap();
        assert_eq!(parsed, TEST_PEM[..TEST_PEM.len() - 1]);
    }

    #[test]
    fn parse_write_der() {
        let parsed = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None)
            .unwrap()
            .write_private_der_vec()
            .unwrap();
        assert!(parsed == TEST_DER);
    }

    #[test]
    fn rsa_sign_verify_pkcs1v15() {
        let mut pk =
            Pk::generate_rsa(&mut crate::test_support::rand::test_rng(), 2048, 0x10001).unwrap();
        let data = b"SIGNATURE TEST SIGNATURE TEST SIGNATURE TEST SIGNATURE TEST SIGN";
        let mut signature = vec![0u8; (pk.len() + 7) / 8];

        let digests = [
            Type::None,
            Type::Md5,
            Type::Sha1,
            Type::Sha224,
            Type::Sha256,
            Type::Sha384,
            Type::Sha512,
            Type::Ripemd,
        ];

        for &digest in &digests {
            let data = if let Some(md @ MdInfo { .. }) = digest.into() {
                &data[..md.size()]
            } else {
                &data[..]
            };

            let len = pk
                .sign(
                    digest,
                    data,
                    &mut signature,
                    &mut crate::test_support::rand::test_rng(),
                )
                .unwrap();
            pk.verify(digest, data, &signature[0..len]).unwrap();

            assert_eq!(pk.verify(digest, data, &[]).unwrap_err(), Error::PkBadInputData);
            assert_eq!(pk.verify(digest, &[], &signature[0..len]).unwrap_err(), Error::PkBadInputData);


            let mut dummy_sig = [];
            assert_eq!(pk.sign(digest, data, &mut dummy_sig, &mut crate::test_support::rand::test_rng()).unwrap_err(), Error::PkBadInputData);
            assert_eq!(pk.sign(digest, &[], &mut signature, &mut crate::test_support::rand::test_rng()).unwrap_err(), Error::PkBadInputData);

            assert_eq!(pk.sign_deterministic(digest, data, &mut dummy_sig, &mut crate::test_support::rand::test_rng()).unwrap_err(), Error::PkBadInputData);
            assert_eq!(pk.sign_deterministic(digest, &[], &mut signature, &mut crate::test_support::rand::test_rng()).unwrap_err(), Error::PkBadInputData);

        }
    }

    #[test]
    fn rsa_sign_verify_pss() {
        let mut pk =
            Pk::generate_rsa(&mut crate::test_support::rand::test_rng(), 2048, 0x10001).unwrap();
        let data = b"SIGNATURE TEST SIGNATURE TEST SIGNATURE TEST SIGNATURE TEST SIGN";
        let mut signature = vec![0u8; (pk.len() + 7) / 8];

        let digests = [
            Type::None,
            Type::Md5,
            Type::Sha1,
            Type::Sha224,
            Type::Sha256,
            Type::Sha384,
            Type::Sha512,
            Type::Ripemd,
        ];

        for &digest in &digests {
            let data = if let Some(md @ MdInfo { .. }) = digest.into() {
                &data[..md.size()]
            } else {
                &data[..]
            };

            pk.set_options(Options::Rsa {
                padding: RsaPadding::Pkcs1V21 { mgf: digest },
            });

            if digest == Type::None {
                assert!(pk
                    .sign(
                        digest,
                        data,
                        &mut signature,
                        &mut crate::test_support::rand::test_rng()
                    )
                    .is_err());
            } else {
                let len = pk
                    .sign(
                        digest,
                        data,
                        &mut signature,
                        &mut crate::test_support::rand::test_rng(),
                    )
                    .unwrap();
                pk.verify(digest, data, &signature[0..len]).unwrap();
            }
        }
    }

    #[test]
    fn encrypt_v15_oaep() {
        let mut pk = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None).unwrap();
        let mut cipher1 = [0u8; 2048 / 8];
        let mut cipher2 = [0u8; 2048 / 8];
        assert_eq!(
            pk.encrypt(b"test", &mut cipher1, &mut crate::test_support::rand::test_rng())
                .unwrap(),
            cipher1.len()
        );
        pk.set_options(Options::Rsa {
            padding: RsaPadding::Pkcs1V21 {
                mgf: Type::Sha256,
            },
        });
        assert_eq!(
            pk.encrypt(b"test", &mut cipher2, &mut crate::test_support::rand::test_rng())
                .unwrap(),
            cipher2.len()
        );
        assert_ne!(&cipher1[..], &cipher2[..]);
    }

    #[test]
    fn encrypt_raw_decrypt_with_pkcs1_v15() {
        let mut pk = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None).unwrap();
        let mut cipher = [0u8; 2048 / 8];
        let mut rng = crate::test_support::rand::test_rng();
        pk.set_options(Options::Rsa {
            padding: RsaPadding::Pkcs1V15
        });
        assert_eq!(
            pk.encrypt(b"test", &mut cipher, &mut rng)
                .unwrap(),
            cipher.len()
        );
        let mut decrypted_data1 = [0u8; 2048 / 8];
        let length_with_padding = pk.decrypt(&cipher, &mut decrypted_data1, &mut rng).unwrap();
        // set raw decryption padding mode to perform raw decryption
        pk.set_options(Options::Rsa {
            padding: RsaPadding::None
        });
        let mut decrypted_data2 = [0u8; 2048 / 8];
        let length_without_padding = pk.decrypt(&cipher, &mut decrypted_data2, &mut rng).unwrap();
        assert_eq!(length_without_padding, decrypted_data2.len());
        // compare lengths of the decrypted texts
        assert_ne!(length_without_padding, length_with_padding);
        assert_eq!(decrypted_data2.len(), cipher.len());
    }

    #[test]
    fn rsa_encrypt_with_no_padding() {
        let mut pk = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None).unwrap();
        let mut cipher = [0u8; 2048 / 8];
        // set raw decryption padding mode
        pk.set_options(Options::Rsa {
            padding: RsaPadding::None
        });
        assert_eq!(
            pk.encrypt(b"test", &mut cipher, &mut crate::test_support::rand::test_rng())
                .unwrap_err(),
            Error::RsaInvalidPadding
        );
    }

    #[test]
    fn rsa_encrypt_decrypt_with_label() {
        let mut pk = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None).unwrap();
        let mut cipher = [0u8; 2048 / 8];
        // set raw decryption padding mode
        pk.set_options(Options::Rsa {
            padding: RsaPadding::Pkcs1V21 { mgf: MdType::Sha256 }
        });

        let plain = b"testing123";
        let cipher_len = pk.encrypt_with_label(plain, &mut cipher,
                                         &mut crate::test_support::rand::test_rng(),
                                         b"MY_LABEL").unwrap();
        assert_eq!(cipher_len, cipher.len());

        let mut plain_decrypted = [0u8; 10];
        let plain_len = pk.decrypt_with_label(&cipher, &mut plain_decrypted,
                                              &mut crate::test_support::rand::test_rng(),
                                              b"MY_LABEL").unwrap();
        assert_eq!(plain_len, plain.len());
        assert_eq!(&plain_decrypted, plain);

        assert_eq!(pk.decrypt_with_label(&cipher, &mut plain_decrypted,
                                              &mut crate::test_support::rand::test_rng(),
                                              b"WRONG_LABEL").unwrap_err(),
                   Error::RsaInvalidPadding);
    }

    #[test]
    fn rsa_sign_with_none_padding() {
        let mut pk =
            Pk::generate_rsa(&mut crate::test_support::rand::test_rng(), 2048, 0x10001).unwrap();
        let data = b"SIGNATURE TEST SIGNATURE TEST SI";
        let mut signature = vec![0u8; (pk.len() + 7) / 8];
        // set raw decryption padding mode
        pk.set_options(Options::Rsa {
            padding: RsaPadding::None,
        });
        assert_eq!(
            pk.sign(Type::Sha256, data, &mut signature, &mut crate::test_support::rand::test_rng())
                .unwrap_err(),
            Error::RsaInvalidPadding
        );
    }

    #[test]
    fn rsa_verify_with_none_padding() {
        let mut pk =
            Pk::generate_rsa(&mut crate::test_support::rand::test_rng(), 2048, 0x10001).unwrap();
        let data = b"SIGNATURE TEST SIGNATURE TEST SI";
        let mut signature = vec![0u8; (pk.len() + 7) / 8];

        let digest = Type::Sha256;
        pk.set_options(Options::Rsa {
            padding: RsaPadding::Pkcs1V21 { mgf: digest },
        });
        let len = pk.sign(digest, data, &mut signature, &mut crate::test_support::rand::test_rng())
            .unwrap();
        // set raw decryption padding mode
        pk.set_options(Options::Rsa {
            padding: RsaPadding::None,
        });
        assert_eq!(
            pk.verify(digest, data, &signature[0..len])
                .unwrap_err(),
            Error::RsaInvalidPadding
        );
    }

    #[test]
    fn rsa_params() {
        let pk = Pk::from_private_key(&mut crate::test_support::rand::test_rng(), TEST_DER, None).unwrap();

        let n = pk.rsa_public_modulus().unwrap();
        let d = pk.rsa_private_exponent().unwrap();
        let p = pk.rsa_private_prime1().unwrap();
        let q = pk.rsa_private_prime2().unwrap();

        let dp = pk.rsa_crt_dp().unwrap();
        let dq = pk.rsa_crt_dq().unwrap();
        let qp = pk.rsa_crt_qp().unwrap();

        let one = Mpi::new(1).unwrap();

        let p1 = (&p - &one).unwrap();
        let q1 = (&q - &one).unwrap();
        assert_eq!(&p * &q, Ok(n));
        assert_eq!(&d % &p1, Ok(dp));
        assert_eq!(&d % &q1, Ok(dq));
        assert_eq!((&qp * &q).unwrap().modulo(&p), Ok(one));
    }

}
