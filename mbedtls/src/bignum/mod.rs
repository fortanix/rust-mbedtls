/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use error::{Error, IntoResult};
use mbedtls_sys::*;

#[cfg(not(feature = "std"))]
use alloc_prelude::*;

use core::cmp::Ordering;
use core::fmt::{Binary, Debug, Display, Formatter, Octal, Result as FmtResult, UpperHex};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign};
use core::ops::{Shl, ShlAssign, Shr, ShrAssign};

pub use mbedtls_sys::mpi_sint;

define!(
    #[c_ty(mpi)]
    struct Mpi;
    const init: fn() -> Self = mpi_init;
    const drop: fn(&mut Self) = mpi_free;
    impl<'a> Into<ptr> {}
);

fn fmt_mpi(n: &Mpi, radix: i32) -> String {
    n.to_string_radix(radix)
        .unwrap_or("(failed to format multi-precision integer)".to_owned())
}

impl Display for Mpi {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", fmt_mpi(self, 10))
    }
}

impl Debug for Mpi {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", fmt_mpi(self, 16))
    }
}

impl UpperHex for Mpi {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", fmt_mpi(self, 16))
    }
}

impl Octal for Mpi {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", fmt_mpi(self, 8))
    }
}

impl Binary for Mpi {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", fmt_mpi(self, 2))
    }
}

#[cfg(feature = "std")]
impl ::core::str::FromStr for Mpi {
    type Err = ::Error;

    fn from_str(s: &str) -> ::Result<Mpi> {
        let is_hex = s.starts_with("0x");
        let radix = if is_hex { 16 } else { 10 };
        let skip = if is_hex { 2 } else { 0 };
        let chars = ::std::ffi::CString::new(&s[skip..]).map_err(|_| Error::Utf8Error(None))?;

        let mut ret = Self::init();

        unsafe { mpi_read_string(&mut ret.inner, radix, chars.as_ptr()) }.into_result()?;

        Ok(ret)
    }
}

impl Mpi {
    pub(crate) fn handle(&self) -> &::mbedtls_sys::mpi {
        &self.inner
    }

    pub(crate) fn handle_mut(&mut self) -> &mut ::mbedtls_sys::mpi {
        &mut self.inner
    }

    pub(crate) fn copy(value: &mpi) -> ::Result<Mpi> {
        let mut ret = Self::init();
        unsafe { mpi_copy(&mut ret.inner, value) }.into_result()?;
        Ok(ret)
    }

    pub fn new(value: mpi_sint) -> ::Result<Mpi> {
        let mut ret = Self::init();
        try!(unsafe { mpi_lset(&mut ret.inner, value).into_result() });
        Ok(ret)
    }

    /// Initialize an MPI number from big endian binary data
    pub fn from_binary(num: &[u8]) -> ::Result<Mpi> {
        let mut ret = Self::init();
        try!(unsafe { mpi_read_binary(&mut ret.inner, num.as_ptr(), num.len()).into_result() });
        Ok(ret)
    }

    pub fn get_bit(&self, bit: usize) -> bool {
        // does not fail
        if unsafe { mpi_get_bit(&self.inner, bit) } == 1 {
            true
        } else {
            false
        }
    }

    pub fn set_bit(&mut self, bit: usize, val: bool) -> ::Result<()> {
        unsafe {
            mpi_set_bit(&mut self.inner, bit, val as u8).into_result()?;
        }
        Ok(())
    }

    fn get_limb(&self, n: usize) -> mpi_uint {
        if n < self.inner.n {
            unsafe { *self.inner.p.offset(n as isize) }
        } else {
            // zero pad
            0
        }
    }

    pub fn as_u32(&self) -> ::Result<u32> {
        if self.bit_length()? > 32 {
            // Not exactly correct but close enough
            return Err(Error::MpiBufferTooSmall);
        }

        Ok(self.get_limb(0) as u32)
    }

    pub fn to_string_radix(&self, radix: i32) -> ::Result<String> {
        let mut olen = 0;
        let r =
            unsafe { mpi_write_string(&self.inner, radix, ::core::ptr::null_mut(), 0, &mut olen) };

        if r != ERR_MPI_BUFFER_TOO_SMALL {
            return Err(Error::from_mbedtls_code(r));
        }

        let mut buf = vec![0u8; olen];

        unsafe {
            mpi_write_string(
                &self.inner,
                radix,
                buf.as_mut_ptr() as *mut i8,
                buf.len(),
                &mut olen,
            )
        }
        .into_result()?;

        let s = String::from_utf8(buf).expect("from_utf8 can't fail on radix-N data");

        #[allow(deprecated)]
        Ok(s.trim_right_matches(char::from(0)).to_owned())
    }

    /// Serialize the MPI as big endian binary data
    pub fn to_binary(&self) -> ::Result<Vec<u8>> {
        let len = self.byte_length()?;
        let mut ret = vec![0u8; len];
        unsafe { mpi_write_binary(&self.inner, ret.as_mut_ptr(), ret.len()).into_result() }?;
        Ok(ret)
    }

    /// Serialize the MPI as big endian binary data, padding to at least min_len bytes
    pub fn to_binary_padded(&self, min_len: usize) -> ::Result<Vec<u8>> {
        let len = self.byte_length()?;
        let larger_len = if len < min_len { min_len } else { len };
        let mut ret = vec![0u8; larger_len];
        let pad_len = ret.len() - len;
        unsafe {
            mpi_write_binary(&self.inner, ret.as_mut_ptr().offset(pad_len as isize), len)
                .into_result()
        }?;
        Ok(ret)
    }

    /// Return size of this MPI in bits
    pub fn bit_length(&self) -> ::Result<usize> {
        let l = unsafe { mpi_bitlen(&self.inner) };
        Ok(l)
    }

    /// Return size of this MPI in bytes (rounded up)
    pub fn byte_length(&self) -> ::Result<usize> {
        let l = unsafe { mpi_size(&self.inner) };
        Ok(l)
    }

    pub fn divrem(&self, other: &Mpi) -> ::Result<(Mpi, Mpi)> {
        let mut q = Self::init();
        let mut r = Self::init();
        unsafe { mpi_div_mpi(&mut q.inner, &mut r.inner, &self.inner, &other.inner) }
            .into_result()?;
        Ok((q, r))
    }

    /// Reduce self modulo other
    pub fn modulo(&self, other: &Mpi) -> ::Result<Mpi> {
        let mut ret = Self::init();
        unsafe { mpi_mod_mpi(&mut ret.inner, &self.inner, &other.inner) }.into_result()?;
        Ok(ret)
    }

    pub fn divrem_int(&self, other: mpi_sint) -> ::Result<(Mpi, Mpi)> {
        let mut q = Self::init();
        let mut r = Self::init();
        unsafe { mpi_div_int(&mut q.inner, &mut r.inner, &self.inner, other) }.into_result()?;
        Ok((q, r))
    }

    pub fn modinv(&self, modulus: &Mpi) -> ::Result<Mpi> {
        let mut r = Self::init();
        unsafe { mpi_inv_mod(&mut r.inner, &self.inner, &modulus.inner) }.into_result()?;
        Ok(r)
    }

    /// Return (self^exponent) % n
    pub fn mod_exp(&self, exponent: &Mpi, modulus: &Mpi) -> ::Result<Mpi> {
        let mut r = Self::init();
        unsafe {
            mpi_exp_mod(
                &mut r.inner,
                &self.inner,
                &exponent.inner,
                &modulus.inner,
                ::core::ptr::null_mut(),
            )
        }
        .into_result()?;

        Ok(r)
    }
}

impl Ord for Mpi {
    fn cmp(&self, other: &Mpi) -> Ordering {
        let r = unsafe { mpi_cmp_mpi(&self.inner, &other.inner) };
        match r {
            -1 => Ordering::Less,
            0 => Ordering::Equal,
            1 => Ordering::Greater,
            _ => unreachable!(),
        }
    }
}

impl PartialOrd for Mpi {
    fn partial_cmp(&self, other: &Mpi) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Mpi {
    fn eq(&self, other: &Mpi) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Mpi {}

macro_rules! impl_arithmetic_op {
    ($op_trait:ident, $op_assign_trait:ident, $trait_func:ident, $trait_assign_func:ident, $func:expr, $int_func:expr) => {
        impl<'a, 'b> $op_trait<&'a Mpi> for &'b Mpi {
            type Output = ::Result<Mpi>;

            fn $trait_func(self, other: &Mpi) -> ::Result<Mpi> {
                let mut ret = Mpi::init();
                unsafe { $func(&mut ret.inner, &self.inner, &other.inner) }.into_result()?;
                Ok(ret)
            }
        }

        impl<'a> $op_trait<mpi_sint> for &'a Mpi {
            type Output = ::Result<Mpi>;

            fn $trait_func(self, other: mpi_sint) -> ::Result<Mpi> {
                let mut ret = Mpi::init();
                unsafe { $int_func(&mut ret.inner, &self.inner, other as _) }.into_result()?;
                Ok(ret)
            }
        }

        impl<'a> $op_assign_trait<&'a Mpi> for Mpi {
            fn $trait_assign_func(&mut self, other: &Mpi) {
                unsafe { $func(self.handle_mut(), self.handle(), other.handle()) }
                    .into_result()
                    .expect("suceeded");
            }
        }

        impl $op_assign_trait<Mpi> for Mpi {
            fn $trait_assign_func(&mut self, other: Mpi) {
                unsafe { $func(self.handle_mut(), self.handle(), other.handle()) }
                    .into_result()
                    .expect("suceeded");
            }
        }

        impl $op_assign_trait<mpi_sint> for Mpi {
            fn $trait_assign_func(&mut self, other: mpi_sint) {
                unsafe { $int_func(self.handle_mut(), self.handle(), other as _) }
                    .into_result()
                    .expect("mpi_add_int worked");
            }
        }
    };
}

impl_arithmetic_op!(Add, AddAssign, add, add_assign, mpi_add_mpi, mpi_add_int);
impl_arithmetic_op!(Sub, SubAssign, sub, sub_assign, mpi_sub_mpi, mpi_sub_int);
impl_arithmetic_op!(Mul, MulAssign, mul, mul_assign, mpi_mul_mpi, mpi_mul_int);

impl<'a, 'b> Div<&'b Mpi> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn div(self, other: &Mpi) -> ::Result<Mpi> {
        let mut q = Mpi::init();
        unsafe {
            mpi_div_mpi(
                &mut q.inner,
                ::core::ptr::null_mut(),
                &self.inner,
                other.handle(),
            )
        }
        .into_result()?;
        Ok(q)
    }
}

impl<'a> Div<Mpi> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn div(self, other: Mpi) -> ::Result<Mpi> {
        let mut q = Mpi::init();
        unsafe {
            mpi_div_mpi(
                &mut q.inner,
                ::core::ptr::null_mut(),
                &self.inner,
                other.handle(),
            )
        }
        .into_result()?;
        Ok(q)
    }
}

impl<'a> Div<mpi_sint> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn div(self, other: mpi_sint) -> ::Result<Mpi> {
        let mut q = Mpi::init();
        unsafe { mpi_div_int(&mut q.inner, ::core::ptr::null_mut(), &self.inner, other) }
            .into_result()?;
        Ok(q)
    }
}

/// Note this will panic if other == 0
impl<'a> DivAssign<&'a Mpi> for Mpi {
    fn div_assign(&mut self, other: &Mpi) {
        // mpi_div_mpi produces incorrect output when arguments alias, so avoid doing that
        let mut q = Mpi::init();
        unsafe {
            mpi_div_mpi(
                &mut q.inner,
                ::core::ptr::null_mut(),
                &self.inner,
                other.handle(),
            )
        }
        .into_result()
        .expect("mpi_div_mpi success");
        *self = q;
    }
}

/// Note this will panic if other == 0
impl DivAssign<Mpi> for Mpi {
    fn div_assign(&mut self, other: Mpi) {
        // mpi_div_mpi produces incorrect output when arguments alias, so avoid doing that
        let mut q = Mpi::init();
        unsafe {
            mpi_div_mpi(
                &mut q.inner,
                ::core::ptr::null_mut(),
                &self.inner,
                other.handle(),
            )
        }
        .into_result()
        .expect("mpi_div_mpi success");
        *self = q;
    }
}

/// Note this will panic if other == 0
impl DivAssign<mpi_sint> for Mpi {
    fn div_assign(&mut self, other: mpi_sint) {
        unsafe {
            mpi_div_int(
                self.handle() as *const ::mbedtls_sys::mpi as _,
                ::core::ptr::null_mut(),
                &self.inner,
                other,
            )
        }
        .into_result()
        .expect("mpi_div_int success");
    }
}

impl<'a, 'b> Rem<&'b Mpi> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn rem(self, other: &Mpi) -> ::Result<Mpi> {
        let mut r = Mpi::init();
        unsafe {
            mpi_div_mpi(
                ::core::ptr::null_mut(),
                &mut r.inner,
                &self.inner,
                other.handle(),
            )
        }
        .into_result()?;
        Ok(r)
    }
}

impl<'a> Rem<Mpi> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn rem(self, other: Mpi) -> ::Result<Mpi> {
        let mut r = Mpi::init();
        unsafe {
            mpi_div_mpi(
                ::core::ptr::null_mut(),
                &mut r.inner,
                &self.inner,
                other.handle(),
            )
        }
        .into_result()?;
        Ok(r)
    }
}

impl Rem<mpi_sint> for Mpi {
    type Output = ::Result<Mpi>;

    fn rem(self, other: mpi_sint) -> ::Result<Mpi> {
        let mut r = Mpi::init();
        unsafe { mpi_div_int(::core::ptr::null_mut(), &mut r.inner, &self.inner, other) }
            .into_result()?;
        Ok(r)
    }
}

impl<'a> Rem<mpi_sint> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn rem(self, other: mpi_sint) -> ::Result<Mpi> {
        let mut r = Mpi::init();
        unsafe { mpi_div_int(::core::ptr::null_mut(), &mut r.inner, &self.inner, other) }
            .into_result()?;
        Ok(r)
    }
}

/// Note this will panic if other == 0
impl<'a> RemAssign<&'a Mpi> for Mpi {
    fn rem_assign(&mut self, other: &Mpi) {
        // mpi_div_mpi produces incorrect output when arguments alias, so avoid doing that
        let mut r = Mpi::init();
        unsafe {
            mpi_div_mpi(
                ::core::ptr::null_mut(),
                &mut r.inner,
                &self.inner,
                other.handle(),
            )
        }
        .into_result()
        .expect("mpi_div_mpi success");
        *self = r;
    }
}

/// Note this will panic if other == 0
impl RemAssign<Mpi> for Mpi {
    fn rem_assign(&mut self, other: Mpi) {
        // mpi_div_mpi produces incorrect output when arguments alias, so avoid doing that
        let mut r = Mpi::init();
        unsafe {
            mpi_div_mpi(
                ::core::ptr::null_mut(),
                &mut r.inner,
                &self.inner,
                other.handle(),
            )
        }
        .into_result()
        .expect("mpi_div_mpi success");
        *self = r;
    }
}

/// Note this will panic if other == 0
impl RemAssign<mpi_sint> for Mpi {
    fn rem_assign(&mut self, other: mpi_sint) {
        unsafe {
            mpi_div_int(
                ::core::ptr::null_mut(),
                self.handle() as *const ::mbedtls_sys::mpi as _,
                &self.inner,
                other,
            )
        }
        .into_result()
        .expect("mpi_div_int success");
    }
}

impl<'a> Shl<usize> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn shl(self, shift: usize) -> ::Result<Mpi> {
        let mut r = Mpi::copy(self.handle())?;
        unsafe { mpi_shift_l(&mut r.inner, shift) }.into_result()?;
        Ok(r)
    }
}

impl Shl<usize> for Mpi {
    type Output = ::Result<Mpi>;

    fn shl(self, shift: usize) -> ::Result<Mpi> {
        let mut r = Mpi::copy(self.handle())?;
        unsafe { mpi_shift_l(&mut r.inner, shift) }.into_result()?;
        Ok(r)
    }
}

impl ShlAssign<usize> for Mpi {
    fn shl_assign(&mut self, shift: usize) {
        unsafe { mpi_shift_l(self.handle() as *const ::mbedtls_sys::mpi as _, shift) }
            .into_result()
            .expect("mpi_shift_l success");
    }
}

impl<'a> Shr<usize> for &'a Mpi {
    type Output = ::Result<Mpi>;

    fn shr(self, shift: usize) -> ::Result<Mpi> {
        let mut r = Mpi::copy(self.handle())?;
        unsafe { mpi_shift_r(&mut r.inner, shift) }.into_result()?;
        Ok(r)
    }
}

impl Shr<usize> for Mpi {
    type Output = ::Result<Mpi>;

    fn shr(self, shift: usize) -> ::Result<Mpi> {
        let mut r = Mpi::copy(self.handle())?;
        unsafe { mpi_shift_r(&mut r.inner, shift) }.into_result()?;
        Ok(r)
    }
}

impl ShrAssign<usize> for Mpi {
    fn shr_assign(&mut self, shift: usize) {
        unsafe { mpi_shift_r(self.handle() as *const ::mbedtls_sys::mpi as _, shift) }
            .into_result()
            .expect("mpi_shift_l success");
    }
}

// TODO
// mbedtls_mpi_swap
// mbedtls_mpi_safe_cond_assign
// mbedtls_mpi_safe_cond_swap
// mbedtls_mpi_lset
// mbedtls_mpi_lsb
// mbedtls_mpi_write_string
// mbedtls_mpi_cmp_abs
// mbedtls_mpi_cmp_int
// mbedtls_mpi_add_abs
// mbedtls_mpi_sub_abs
// mbedtls_mpi_mod_int
// mbedtls_mpi_gcd
// mbedtls_mpi_is_prime
