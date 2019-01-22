/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::marker::PhantomData;
use core::ops::Range;
pub mod raw;

// Type-level operations
pub trait Operation: Sized {
    fn is_encrypt() -> bool;
}

pub enum Encryption {}
impl Operation for Encryption {
    fn is_encrypt() -> bool {
        true
    }
}

pub enum Decryption {}
impl Operation for Decryption {
    fn is_encrypt() -> bool {
        false
    }
}

// Type-level cipher types
pub trait Type {
    fn is_valid_mode(mode: raw::CipherMode) -> bool;
}

pub enum TraditionalNoIv {}
impl Type for TraditionalNoIv {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::ECB => true,
            _ => false,
        }
    }
}

pub enum Traditional {}
impl Type for Traditional {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::CBC
            | raw::CipherMode::CFB
            | raw::CipherMode::OFB
            | raw::CipherMode::CTR => true,
            _ => false,
        }
    }
}

pub enum Authenticated {}
impl Type for Authenticated {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::GCM | raw::CipherMode::CCM => true,
            _ => false,
        }
    }
}

// Type-level states
pub trait State {}

pub enum Fresh {}
impl State for Fresh {}

pub enum AdditionalData {}
impl State for AdditionalData {}

pub enum CipherData {}
impl State for CipherData {}

pub enum Finished {}
impl State for Finished {}

pub struct Cipher<O: Operation, T: Type, S: State = Fresh> {
    raw_cipher: raw::Cipher,

    // mbedtls only stores the padding as function pointers, so we remember this here
    padding: raw::CipherPadding,
    _op: PhantomData<O>,
    _type: PhantomData<T>,
    _state: PhantomData<S>,
}

impl<O: Operation, T: Type, S: State> Cipher<O, T, S> {
    fn change_state<N: State>(self) -> Cipher<O, T, N> {
        self.change_type_and_state()
    }

    fn change_type_and_state<N: Type, M: State>(self) -> Cipher<O, N, M> {
        Cipher {
            raw_cipher: self.raw_cipher,
            padding: self.padding,
            _op: PhantomData,
            _type: PhantomData,
            _state: PhantomData,
        }
    }

    pub fn block_size(&self) -> usize {
        self.raw_cipher.block_size()
    }

    pub fn iv_size(&self) -> usize {
        self.raw_cipher.iv_size()
    }

    pub fn tag_size(&self) -> Option<Range<usize>> {
        if self.raw_cipher.is_authenticated() {
            Some(32..129)
        } else {
            None
        }
    }
}

impl<O: Operation, T: Type> Cipher<O, T, Fresh> {
    pub fn new(
        cipher_id: raw::CipherId,
        cipher_mode: raw::CipherMode,
        key_bit_len: u32,
    ) -> ::Result<Cipher<O, T, Fresh>> {
        assert!(T::is_valid_mode(cipher_mode));

        // Create raw cipher object
        let raw_cipher = try!(raw::Cipher::setup(cipher_id, cipher_mode, key_bit_len));

        // Put together the structure to return
        Ok(Cipher {
            raw_cipher: raw_cipher,
            padding: raw::CipherPadding::Pkcs7,
            _op: PhantomData,
            _type: PhantomData,
            _state: PhantomData,
        })
    }

    pub fn set_parity(key: &mut [u8]) -> ::Result<()> {
        raw::Cipher::set_parity(key)
    }
}

impl<Op: Operation, T: Type> Cipher<Op, T, Fresh> {
    fn set_key_and_maybe_iv(&mut self, key: &[u8], iv: Option<&[u8]>) -> ::Result<()> {
        let cipher_op = if Op::is_encrypt() {
            raw::Operation::Encrypt
        } else {
            raw::Operation::Decrypt
        };

        // Set key
        self.raw_cipher.set_key(cipher_op, key)?;

        // Set IV
        if let Some(iv) = iv {
            self.raw_cipher.set_iv(iv)?;
        }

        // Also do a reset right here so the user can start the crypto operation right away in "CipherData"
        self.raw_cipher.reset()
    }

    pub fn set_padding(&mut self, padding: raw::CipherPadding) -> ::Result<()> {
        self.padding = padding;
        self.raw_cipher.set_padding(padding)
    }
}

impl<O: Operation> Cipher<O, TraditionalNoIv, Fresh> {
    pub fn set_key(mut self, key: &[u8]) -> ::Result<Cipher<O, Traditional, CipherData>> {
        self.set_key_and_maybe_iv(key, None)?;

        // Put together the structure to return
        Ok(self.change_type_and_state())
    }
}

impl<O: Operation> Cipher<O, Traditional, Fresh> {
    pub fn set_key_iv(
        mut self,
        key: &[u8],
        iv: &[u8],
    ) -> ::Result<Cipher<O, Traditional, CipherData>> {
        self.set_key_and_maybe_iv(key, Some(iv))?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

impl<O: Operation> Cipher<O, Authenticated, Fresh> {
    pub fn set_key_iv(
        mut self,
        key: &[u8],
        iv: &[u8],
    ) -> ::Result<Cipher<O, Authenticated, AdditionalData>> {
        self.set_key_and_maybe_iv(key, Some(iv))?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

impl Cipher<Encryption, Traditional, CipherData> {
    pub fn encrypt(
        mut self,
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> ::Result<(usize, Cipher<Encryption, Traditional, Finished>)> {
        // Call the wrapper function to encrypt all
        let len = try!(self.raw_cipher.encrypt(plain_text, cipher_text));

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

impl Cipher<Decryption, Traditional, CipherData> {
    pub fn decrypt(
        mut self,
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> ::Result<(usize, Cipher<Decryption, Traditional, Finished>)> {
        // Call the wrapper function to decrypt all
        let len = try!(self.raw_cipher.decrypt(cipher_text, plain_text));

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

impl Cipher<Encryption, Authenticated, AdditionalData> {
    pub fn encrypt_auth(
        mut self,
        ad: &[u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
        tag: &mut [u8],
    ) -> ::Result<(usize, Cipher<Encryption, Authenticated, Finished>)> {
        Ok((
            self.raw_cipher
                .encrypt_auth(ad, plain_text, cipher_text, tag)?,
            self.change_state(),
        ))
    }
}

impl Cipher<Decryption, Authenticated, AdditionalData> {
    pub fn decrypt_auth(
        mut self,
        ad: &[u8],
        cipher_text: &[u8],
        plain_text: &mut [u8],
        tag: &[u8],
    ) -> ::Result<(usize, Cipher<Decryption, Authenticated, Finished>)> {
        Ok((
            self.raw_cipher
                .decrypt_auth(ad, cipher_text, plain_text, tag)?,
            self.change_state(),
        ))
    }
}

impl<O: Operation, T: Type> Cipher<O, T, CipherData> {
    pub fn update(
        mut self,
        in_data: &[u8],
        out_data: &mut [u8],
    ) -> ::Result<(usize, Cipher<O, T, CipherData>)> {
        // Call the wrapper function to do update operation (multi part)
        let len = try!(self.raw_cipher.update(in_data, out_data));

        // Put together the structure to return
        Ok((len, self.change_state()))
    }

    pub fn finish(mut self, out_data: &mut [u8]) -> ::Result<(usize, Cipher<O, T, Finished>)> {
        // Call the wrapper function to finish operation (multi part)
        let len = try!(self.raw_cipher.finish(out_data));

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

#[test]
fn ccm() {
    // Example vector C.1
    let k = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let iv = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let ad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let p = [0x20, 0x21, 0x22, 0x23];
    let mut p_out = [0u8; 4];
    let c = [0x71, 0x62, 0x01, 0x5b];
    let mut c_out = [0u8; 4];
    let t = [0x4d, 0xac, 0x25, 0x5d];
    let mut t_out = [0u8; 4];

    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CCM,
        (k.len() * 8) as _,
    )
    .unwrap();
    let cipher = cipher.set_key_iv(&k, &iv).unwrap();
    cipher
        .encrypt_auth(&ad, &p, &mut c_out, &mut t_out)
        .unwrap();
    assert_eq!(c, c_out);
    assert_eq!(t, t_out);
    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CCM,
        (k.len() * 8) as _,
    )
    .unwrap();
    let cipher = cipher.set_key_iv(&k, &iv).unwrap();
    cipher.decrypt_auth(&ad, &c, &mut p_out, &t).unwrap();
    assert_eq!(p, p_out);
}
