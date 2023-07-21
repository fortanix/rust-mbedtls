/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::convert::TryFrom;

use mbedtls_sys::*;

use crate::error::{IntoResult, Result, codes};

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

mod serde;

define!(
    #[c_ty(cipher_id_t)]
    enum CipherId {
        None = CIPHER_ID_NONE,
        Null = CIPHER_ID_NULL,
        Aes = CIPHER_ID_AES,
        Des = CIPHER_ID_DES,
        Des3 = CIPHER_ID_3DES,
        Camellia = CIPHER_ID_CAMELLIA,
        Aria = CIPHER_ID_ARIA,
        ChaCha20 = CIPHER_ID_CHACHA20,
    }
);

impl TryFrom<cipher_id_t> for CipherId {
    type Error =  crate::error::Error;

    fn try_from(inner: cipher_id_t) -> Result<Self> {
        match inner {
            CIPHER_ID_NONE => Ok(CipherId::None),
            CIPHER_ID_NULL => Ok(CipherId::Null),
            CIPHER_ID_AES => Ok(CipherId::Aes),
            CIPHER_ID_DES => Ok(CipherId::Des),
            CIPHER_ID_3DES => Ok(CipherId::Des3),
            CIPHER_ID_CAMELLIA => Ok(CipherId::Camellia),
            CIPHER_ID_ARIA => Ok(CipherId::Aria),
            CIPHER_ID_CHACHA20 => Ok(CipherId::ChaCha20),
            _ => Err(codes::CipherBadInputData.into()),
        }
    }
}

define!(
    #[c_ty(cipher_mode_t)]
    #[derive(Copy, Clone, Eq, PartialEq)]
    #[allow(non_camel_case_types)]
    enum CipherMode {
        None = MODE_NONE,
        ECB = MODE_ECB,
        CBC = MODE_CBC,
        CFB = MODE_CFB,
        OFB = MODE_OFB,
        CTR = MODE_CTR,
        GCM = MODE_GCM,
        STREAM = MODE_STREAM,
        CCM = MODE_CCM,
        CCM_STAR_NO_TAG = MODE_CCM_STAR_NO_TAG,
        KW = MODE_KW,
        KWP = MODE_KWP,
        XTS = MODE_XTS,
        CHACHAPOLY = MODE_CHACHAPOLY,
    }
);

impl From<cipher_mode_t> for CipherMode {
    fn from(inner: cipher_mode_t) -> Self {
        match inner {
            MODE_NONE => CipherMode::None,
            MODE_ECB => CipherMode::ECB,
            MODE_CBC => CipherMode::CBC,
            MODE_CFB => CipherMode::CFB,
            MODE_OFB => CipherMode::OFB,
            MODE_CTR => CipherMode::CTR,
            MODE_GCM => CipherMode::GCM,
            MODE_STREAM => CipherMode::STREAM,
            MODE_CCM_STAR_NO_TAG => CipherMode::CCM_STAR_NO_TAG,
            MODE_CCM => CipherMode::CCM,
            MODE_KW => CipherMode::KW,
            MODE_KWP => CipherMode::KWP,
            MODE_XTS => CipherMode::XTS,
            MODE_CHACHAPOLY => CipherMode::CHACHAPOLY,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid cipher_mode_t"),
        }
    }
}

define!(
    #[c_ty(cipher_type_t)]
    enum CipherType {
        None = CIPHER_NONE,
        Null = CIPHER_NULL,
        Aes128Ecb = CIPHER_AES_128_ECB,
        Aes192Ecb = CIPHER_AES_192_ECB,
        Aes256Ecb = CIPHER_AES_256_ECB,
        Aes128Cbc = CIPHER_AES_128_CBC,
        Aes192Cbc = CIPHER_AES_192_CBC,
        Aes256Cbc = CIPHER_AES_256_CBC,
        Aes128Cfb128 = CIPHER_AES_128_CFB128,
        Aes192Cfb128 = CIPHER_AES_192_CFB128,
        Aes256Cfb128 = CIPHER_AES_256_CFB128,
        Aes128Ctr = CIPHER_AES_128_CTR,
        Aes192Ctr = CIPHER_AES_192_CTR,
        Aes256Ctr = CIPHER_AES_256_CTR,
        Aes128Gcm = CIPHER_AES_128_GCM,
        Aes192Gcm = CIPHER_AES_192_GCM,
        Aes256Gcm = CIPHER_AES_256_GCM,
        Camellia128Ecb = CIPHER_CAMELLIA_128_ECB,
        Camellia192Ecb = CIPHER_CAMELLIA_192_ECB,
        Camellia256Ecb = CIPHER_CAMELLIA_256_ECB,
        Camellia128Cbc = CIPHER_CAMELLIA_128_CBC,
        Camellia192Cbc = CIPHER_CAMELLIA_192_CBC,
        Camellia256Cbc = CIPHER_CAMELLIA_256_CBC,
        Camellia128Cfb128 = CIPHER_CAMELLIA_128_CFB128,
        Camellia192Cfb128 = CIPHER_CAMELLIA_192_CFB128,
        Camellia256Cfb128 = CIPHER_CAMELLIA_256_CFB128,
        Camellia128Ctr = CIPHER_CAMELLIA_128_CTR,
        Camellia192Ctr = CIPHER_CAMELLIA_192_CTR,
        Camellia256Ctr = CIPHER_CAMELLIA_256_CTR,
        Camellia128Gcm = CIPHER_CAMELLIA_128_GCM,
        Camellia192Gcm = CIPHER_CAMELLIA_192_GCM,
        Camellia256Gcm = CIPHER_CAMELLIA_256_GCM,
        DesEcb = CIPHER_DES_ECB,
        DesCbc = CIPHER_DES_CBC,
        DesEdeEcb = CIPHER_DES_EDE_ECB,
        DesEdeCbc = CIPHER_DES_EDE_CBC,
        DesEde3Ecb = CIPHER_DES_EDE3_ECB,
        DesEde3Cbc = CIPHER_DES_EDE3_CBC,
        Aes128Ccm = CIPHER_AES_128_CCM,
        Aes192Ccm = CIPHER_AES_192_CCM,
        Aes256Ccm = CIPHER_AES_256_CCM,
        Aes128CcmStarNoTag = CIPHER_AES_128_CCM_STAR_NO_TAG,
        Aes192CcmStarNoTag = CIPHER_AES_192_CCM_STAR_NO_TAG,
        Aes256CcmStarNoTag = CIPHER_AES_256_CCM_STAR_NO_TAG,
        Camellia128Ccm = CIPHER_CAMELLIA_128_CCM,
        Camellia192Ccm = CIPHER_CAMELLIA_192_CCM,
        Camellia256Ccm = CIPHER_CAMELLIA_256_CCM,
        Camellia128CcmStarNoTag = CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,
        Camellia192CcmStarNoTag = CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,
        Camellia256CcmStarNoTag = CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,
        Aria128Ecb = CIPHER_ARIA_128_ECB,
        Aria192Ecb = CIPHER_ARIA_192_ECB,
        Aria256Ecb = CIPHER_ARIA_256_ECB,
        Aria128Cbc = CIPHER_ARIA_128_CBC,
        Aria192Cbc = CIPHER_ARIA_192_CBC,
        Aria256Cbc = CIPHER_ARIA_256_CBC,
        Aria128Cfb128 = CIPHER_ARIA_128_CFB128,
        Aria192Cfb128 = CIPHER_ARIA_192_CFB128,
        Aria256Cfb128 = CIPHER_ARIA_256_CFB128,
        Aria128Ctr = CIPHER_ARIA_128_CTR,
        Aria192Ctr = CIPHER_ARIA_192_CTR,
        Aria256Ctr = CIPHER_ARIA_256_CTR,
        Aria128Gcm = CIPHER_ARIA_128_GCM,
        Aria192Gcm = CIPHER_ARIA_192_GCM,
        Aria256Gcm = CIPHER_ARIA_256_GCM,
        Aria128Ccm = CIPHER_ARIA_128_CCM,
        Aria192Ccm = CIPHER_ARIA_192_CCM,
        Aria256Ccm = CIPHER_ARIA_256_CCM,
        Aria128CcmStarNoTag = CIPHER_ARIA_128_CCM_STAR_NO_TAG,
        Aria192CcmStarNoTag = CIPHER_ARIA_192_CCM_STAR_NO_TAG,
        Aria256CcmStarNoTag = CIPHER_ARIA_256_CCM_STAR_NO_TAG,
        Aes128Ofb = CIPHER_AES_128_OFB,
        Aes192Ofb = CIPHER_AES_192_OFB,
        Aes256Ofb = CIPHER_AES_256_OFB,
        Aes128Xts = CIPHER_AES_128_XTS,
        Aes256Xts = CIPHER_AES_256_XTS,
        Chacha20 = CIPHER_CHACHA20,
        Chacha20Poly1305 = CIPHER_CHACHA20_POLY1305,
        Aes128Kw = CIPHER_AES_128_KW,
        Aes192Kw = CIPHER_AES_192_KW,
        Aes256Kw = CIPHER_AES_256_KW,
        Aes128Kwp = CIPHER_AES_128_KWP,
        Aes192Kwp = CIPHER_AES_192_KWP,
        Aes256Kwp = CIPHER_AES_256_KWP,
    }
);

define!(
    #[c_ty(cipher_padding_t)]
    #[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
    enum CipherPadding {
        Pkcs7 = PADDING_PKCS7,
        IsoIec78164 = PADDING_ONE_AND_ZEROS,
        AnsiX923 = PADDING_ZEROS_AND_LEN,
        Zeros = PADDING_ZEROS,
        None = PADDING_NONE,
    }
);

define!(
    #[c_ty(operation_t)]
    enum Operation {
        None = OPERATION_NONE,
        Decrypt = DECRYPT,
        Encrypt = ENCRYPT,
    }
);

define!(
    #[c_ty(cipher_context_t)]
    #[repr(C)]
    struct Cipher {
        // IV need to be record on rust side because the `iv` and `iv_len` field
        // of `cipher_context_t` are no longer stable and are marked as `private_`,
        // in another word there is no garruent that these fields are always correctly
        // been updated.
        iv: Option<Vec<u8>>,
    };
    const drop: fn(&mut Self) = cipher_free;
    impl<'a> Into<ptr> {}
);

impl Cipher {
    pub fn init() -> Self {
        let mut inner = ::core::mem::MaybeUninit::uninit();
        let inner = unsafe {
            ::mbedtls_sys::cipher_init(inner.as_mut_ptr());
            inner.assume_init()
        };
        Cipher {
            inner,
            iv: None,
        }
    }

    // Setup routine - this should be the first function called
    // it combines several steps into one call here, they are
    // Cipher init, Cipher setup
    pub fn setup(
        cipher_id: CipherId,
        cipher_mode: CipherMode,
        key_bit_len: u32,
    ) -> Result<Cipher> {
        let mut ret = Self::init();
        unsafe {
            // Do setup with proper cipher_info based on algorithm, key length and mode
            cipher_setup(
                &mut ret.inner,
                cipher_info_from_values(cipher_id.into(), key_bit_len as i32, cipher_mode.into())
            )
            .into_result()?;
        }
        Ok(ret)
    }

    // Cipher set key - should be called after setup
    pub fn set_key(&mut self, op: Operation, key: &[u8]) -> Result<()> {
        unsafe {
            cipher_setkey(
                &mut self.inner,
                key.as_ptr(),
                (key.len() * 8) as _,
                op.into(),
            )
            .into_result_discard()
        }
    }

    pub fn set_padding(&mut self, padding: CipherPadding) -> Result<()> {
        unsafe { cipher_set_padding_mode(&mut self.inner, padding.into()).into_result_discard() }
    }

    // Cipher set IV - should be called after setup
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        self.iv = Some(iv.to_vec());
        unsafe { cipher_set_iv(&mut self.inner, iv.as_ptr(), iv.len()).into_result_discard() }
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe { cipher_reset(&mut self.inner).into_result_discard() }
    }

    pub fn update_ad(&mut self, ad: &[u8]) -> Result<()> {
        unsafe { cipher_update_ad(&mut self.inner, ad.as_ptr(), ad.len()).into_result_discard() }
    }

    pub fn update(&mut self, indata: &[u8], outdata: &mut [u8]) -> Result<usize> {
        // Check that minimum required space is available in outdata buffer
        let reqd_size = if self.cipher_mode() == CipherMode::ECB {
            self.block_size()
        } else {
            indata.len() + self.block_size()
        };

        if outdata.len() < reqd_size {
            return Err(codes::CipherFullBlockExpected.into());
        }

        let mut olen = 0;
        unsafe {
            cipher_update(
                &mut self.inner,
                indata.as_ptr(),
                indata.len(),
                outdata.as_mut_ptr(),
                &mut olen
            )
            .into_result()?;
        }
        Ok(olen)
    }

    pub fn finish(&mut self, outdata: &mut [u8]) -> Result<usize> {
        // Check that minimum required space is available in outdata buffer
        if outdata.len() < self.block_size() {
            return Err(codes::CipherFullBlockExpected.into());
        }

        let mut olen = 0;
        unsafe {
            cipher_finish(&mut self.inner, outdata.as_mut_ptr(), &mut olen).into_result()?;
        }
        Ok(olen)
    }

    pub fn write_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        unsafe {
            cipher_write_tag(&mut self.inner, tag.as_mut_ptr(), tag.len()).into_result_discard()
        }
    }

    pub fn check_tag(&mut self, tag: &[u8]) -> Result<()> {
        unsafe { cipher_check_tag(&mut self.inner, tag.as_ptr(), tag.len()).into_result_discard() }
    }

    // Utility function to get block size for the selected / setup cipher_info
    pub fn block_size(&self) -> usize {
        unsafe { cipher_get_block_size(&self.inner) as usize}
    }

    // Utility function to get IV size for the selected / setup cipher_info
    pub fn iv_size(&self) -> usize {
        if let Some(ref iv) = self.iv {
            iv.len()
        } else {
            unsafe { cipher_get_iv_size(&self.inner) as usize }
        }
    }

    pub fn cipher_mode(&self) -> CipherMode {
        unsafe { cipher_get_cipher_mode(&self.inner).into() }
    }

    /// Public function that determines if the selected cipher mode is an authenticated mode.
    ///
    /// # Returns
    ///
    /// This function returns a boolean value indicating whether the cipher mode is authenticated.
    ///
    /// Authenticated cipher modes provide both encryption and a level of integrity and authenticity.
    /// Specifically, the following cipher modes are considered authenticated:
    /// - GCM (Galois/Counter Mode): an authenticated encryption mode that provides confidentiality, integrity, and authenticity.
    /// - CCM (Counter with CBC-MAC): an authenticated encryption mode that combines CTR for encryption and CBC-MAC for authentication.
    /// - CCM_STAR_NO_TAG: a variant of CCM that omits the authentication tag, and thus, while derived from an authenticated encryption mode, does not provide authentication.
    /// - CHACHAPOLY (ChaCha20-Poly1305): an authenticated encryption mode that combines the ChaCha20 stream cipher with the Poly1305 message authentication code.
    /// - KW (AES Key Wrap): a deterministic authenticated encryption mode designed specifically for wrapping (encrypting) keys, as defined by NIST.
    /// - KWP (AES Key Wrap with Padding): a variant of KW that includes padding, also defined by NIST and designed for key wrapping.
    ///
    /// If the cipher mode does not fall into one of these categories, the function will return false, indicating that it is not authenticated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mbedtls::cipher::raw::*;
    /// let cipher = Cipher::setup(CipherId::Aes, CipherMode::GCM, 128).unwrap();
    /// assert!(cipher.is_authenticated());
    ///
    /// let cipher = Cipher::setup(CipherId::Aes, CipherMode::CBC, 128).unwrap();
    /// assert!(!cipher.is_authenticated());
    /// ```
    pub fn is_authenticated(&self) -> bool {
        match self.cipher_mode() {
            CipherMode::GCM | CipherMode::CCM | CipherMode::CCM_STAR_NO_TAG |
            CipherMode::CHACHAPOLY | CipherMode::KW | CipherMode::KWP => true,
            _ => false,
        }
    }

    // Utility function to set odd parity - used for DES keys
    pub fn set_parity(key: &mut [u8]) -> Result<()> {
        unsafe { des_key_set_parity(key.as_mut_ptr()) }
        Ok(())
    }

    pub fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        self.do_crypto(plain, cipher)
    }

    pub fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        self.do_crypto(cipher, plain)
    }

    /// The authenticated encryption (AEAD/NIST_KW) function.
    ///
    /// For AEAD modes, the tag will be appended to the ciphertext, as recommended by RFC 5116.
    /// (NIST_KW doesn't have a separate tag.)
    ///
    /// # Arguments
    ///
    /// * `ad` - The additional data to authenticate.
    /// * `plain` - The plaintext data to be encrypted and authenticated.
    /// * `cipher_and_tag` - A mutable reference to a byte array where the ciphertext and authentication tag will be written.
    /// * `tag_len` - The length of the tag to be generated.
    ///
    /// # Returns
    ///
    /// * `Result<usize>` - The length of the encrypted data on success.
    ///
    /// # Errors
    ///
    /// * `codes::CipherBadInputData` - For authenticated cipher mode plain_text length should be smaller than cipher length, except
    ///   AES KW and KWP cipher mode.
    /// * Any other errors from underlying `mbedtls_cipher_auth_encrypt_ext` function.
    pub fn encrypt_auth(
        &mut self,
        ad: &[u8],
        plain_text: &[u8],
        cipher_and_tag: &mut [u8],
        tag_len: usize,
    ) -> Result<usize> {
        let cipher_mode = self.cipher_mode();
        if cipher_mode != CipherMode::KW
        && cipher_mode != CipherMode::KWP
        && self.is_authenticated()
        && cipher_and_tag.len()
                .checked_sub(tag_len)
                .map_or(true, |cipher_len| cipher_len < plain_text.len()) {
            return Err(codes::CipherBadInputData.into());
        }
        let iv = self.iv.as_ref().ok_or(codes::CipherBadInputData)?;
        let iv_len = iv.len();
        let mut cipher_len = cipher_and_tag.len();
        unsafe {
            cipher_auth_encrypt_ext(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                plain_text.as_ptr(),
                plain_text.len(),
                cipher_and_tag.as_mut_ptr(),
                cipher_len,
                &mut cipher_len,
                tag_len,
            )
            .into_result()?
        };

        Ok(cipher_len)
    }

    /// The authenticated decryption (AEAD/NIST_KW) function.
    ///
    /// # Arguments
    ///
    /// * `ad` - The additional data that was authenticated.
    /// * `cipher_and_tag` - The ciphertext and authentication tag that were generated by the corresponding call to `encrypt_auth`.
    /// * `plain_text` - A mutable reference to a byte array where the decrypted plaintext will be written.
    /// * `tag_len` - The length of the tag.
    ///
    /// # Returns
    ///
    /// * `Result<usize>` - The length of the decrypted data on success.
    ///
    /// # Errors
    ///
    /// * `codes::CipherBadInputData` - For authenticated cipher mode plain_text length should be smaller than cipher length, except
    ///   AES KW and KWP cipher mode.
    /// * Any other errors from underlying `mbedtls_cipher_auth_decrypt_ext` mbedtls function.
    pub fn decrypt_auth(
        &mut self,
        ad: &[u8],
        cipher_and_tag: &[u8],
        plain_text: &mut [u8],
        tag_len: usize,
    ) -> Result<usize> {
        // For authenticated cipher mode plain_text length should be smaller than cipher length, except
        // AES KW and KWP cipher mode
        let cipher_mode = self.cipher_mode();
        if cipher_mode != CipherMode::KW
        && cipher_mode != CipherMode::KWP
        && self.is_authenticated()
        && cipher_and_tag.len()
                .checked_sub(tag_len)
                .map_or(true, |cipher_len| plain_text.len() < cipher_len) {
            return Err(codes::CipherBadInputData.into());
        }

        let iv = self.iv.as_ref().ok_or(codes::CipherBadInputData)?;
        let iv_len = iv.len();
        let mut plain_len = plain_text.len();
        unsafe {
            cipher_auth_decrypt_ext(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                cipher_and_tag.as_ptr(),
                cipher_and_tag.len(),
                plain_text.as_mut_ptr(),
                plain_len,
                &mut plain_len,
                tag_len,
            )
            .into_result()?
        };

        Ok(plain_len)
    }

    /// The authenticated encryption (AEAD/NIST_KW) function.
    ///
    /// For AEAD modes, the tag will be appended to the ciphertext, as recommended by RFC 5116.
    /// (NIST_KW doesn't have a separate tag.)
    ///
    /// # Arguments
    ///
    /// * `ad` - The additional data to authenticate
    /// * `data_with_tag` - The data to be encrypted and authenticated, along with space for the tag
    /// * `tag_len` - The length of the tag to be generated
    ///
    /// # Returns
    ///
    /// * `Result<usize>` - The length of the encrypted data on success
    ///
    /// # Errors
    ///
    /// * `codes::CipherBadInputData` - If the size of `data_with_tag` minus `tag_len` is less than
    ///   or equal to zero
    pub fn encrypt_auth_inplace(
        &mut self,
        ad: &[u8],
        data_with_tag: &mut [u8],
        tag_len: usize,
    ) -> Result<usize> {
        if data_with_tag.len() - tag_len <= 0 {
            return Err(codes::CipherBadInputData.into());
        }
        let iv = self.iv.as_ref().ok_or(codes::CipherBadInputData)?;
        let iv_len = iv.len();
        let mut olen = data_with_tag.len();
        unsafe {
            cipher_auth_encrypt_ext(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                data_with_tag.as_ptr(),
                data_with_tag.len() - tag_len,
                data_with_tag.as_mut_ptr(),
                olen,
                &mut olen,
                tag_len,
            )
            .into_result()?
        };

        Ok(olen)
    }

    /// The authenticated decryption (AEAD/NIST_KW) function.
    ///
    /// If the data is not authentic, then the output buffer is zeroed out to
    /// prevent the unauthentic plaintext being used, making this interface safer.
    ///
    /// For AEAD modes, the tag must be appended to the ciphertext, as recommended by RFC 5116.
    /// (NIST_KW doesn't have a separate tag.)
    ///
    /// # Arguments
    ///
    /// * `ad` - The additional data to authenticate
    /// * `data_with_tag` - The data to be decrypted and authenticated, along with space for the tag
    /// * `tag_len` - The length of the tag to be generated
    ///
    /// # Returns
    ///
    /// * `Result<usize>` - The length of the decrypted data on success
    ///
    /// # Errors
    ///
    /// * `codes::CipherBadInputData` - If the size of `data_with_tag` minus `tag_len` is less than
    ///   or equal to zero
    pub fn decrypt_auth_inplace(
        &mut self,
        ad: &[u8],
        data_with_tag: &mut [u8],
        tag_len: usize,
    ) -> Result<usize> {
        if data_with_tag.len() - tag_len <= 0 {
            return Err(codes::CipherBadInputData.into());
        }
        let iv = self.iv.as_ref().ok_or(codes::CipherBadInputData)?;
        let iv_len = iv.len();
        let mut plain_len = data_with_tag.len();
        unsafe {
            cipher_auth_decrypt_ext(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                data_with_tag.as_ptr(),
                data_with_tag.len(),
                data_with_tag.as_mut_ptr(),
                data_with_tag.len() - tag_len,
                &mut plain_len,
                tag_len,
            )
            .into_result()?
        };

        Ok(plain_len)
    }

    fn do_crypto(&mut self, indata: &[u8], outdata: &mut [u8]) -> Result<usize> {
        self.reset()?;

        // The total number of bytes writte to outdata so far. It's safe to
        // use this as a start index for slicing: &slice[slice.len()..] will
        // return an empty slice, it doesn't panic.
        let mut total_len = 0;

        if self.cipher_mode() == CipherMode::ECB {
            // ECB mode requires single-block updates
            for chunk in indata.chunks(self.block_size()) {
                let len = self.update(chunk, &mut outdata[total_len..])?;
                total_len += len;
            }
        } else {
            total_len = self.update(indata, outdata)?;
            total_len += self.finish(&mut outdata[total_len..])?;
        }

        Ok(total_len)
    }

    pub fn cmac(&mut self, key: &[u8], data: &[u8], outdata: &mut [u8]) -> Result<()> {
        // Check that outdata buffer has enough space
        if outdata.len() < self.block_size() {
            return Err(codes::CipherFullBlockExpected.into());
        }
        self.reset()?;
        unsafe {
            cipher_cmac(&*self.inner.private_cipher_info, key.as_ptr(), (key.len() * 8) as _, data.as_ptr(), data.len(), 
                        outdata.as_mut_ptr()).into_result()?;
        }
        Ok(())
    }

}

#[test]
fn no_overflow() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::CBC, 128).unwrap();
    c.set_key(Operation::Encrypt, &[0u8; 16]).unwrap();
    c.set_iv(&[0u8; 16]).unwrap();
    let mut out = [0u8; 48];
    let encrypt_result = c.encrypt(&[0u8; 16][..], &mut out[..16]);
    assert_eq!(out[16..], [0u8; 32]);
    encrypt_result.expect_err("Returned OK with too small buffer");
}

#[test]
fn one_part_ecb() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::ECB, 128).unwrap();
    c.set_key(
        Operation::Encrypt,
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    )
    .unwrap();
    let mut out = [0u8; 48];
    let len = c.encrypt(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", &mut out).unwrap();
    assert_eq!(len, 32);
    assert_eq!(&out[..len], b"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a");
}

#[test]
fn cmac_test() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::ECB, 128).unwrap();
    let mut out = [0u8; 16];
    c.cmac(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
           b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", &mut out).expect("Success in CMAC");
    assert_eq!(&out, b"\x38\x7b\x36\x22\x8b\xa7\x77\x44\x5b\xaf\xa0\x36\x45\xb9\x40\x10");
}
