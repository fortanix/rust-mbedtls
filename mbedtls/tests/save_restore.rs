/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls::cipher;
use mbedtls::cipher::raw::{CipherId, CipherMode, CipherPadding};
use mbedtls::cipher::{Cipher, Decryption, Encryption, Fresh, Authenticated, Traditional};
use serde_cbor::{de, ser};

const ZERO_16B: &'static [u8] = &[0u8; 16];

#[test]
fn save_restore_aes_cbc_enc_nopad() {
    let mut ct: [u8; 48] = [0; 48];
    let expected_ct: [u8; 32] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc,
    ];

    let mut cipher =
        cipher::Cipher::<Encryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 128)
            .unwrap();
    cipher.set_padding(CipherPadding::None).unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    let (len1, cipher_d1) = cipher_k.update(ZERO_16B, &mut ct[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();
    // use rustc_serialize::hex::ToHex;
    // println!("{:?}", saved.as_slice().to_hex());

    let cipher_r = de::from_slice::<Cipher<Encryption, Traditional, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(ZERO_16B, &mut ct[16..48]).unwrap();
    assert_eq!(len2, 16);

    let (len3, _) = cipher_d2.finish(&mut ct[32..48]).unwrap();
    assert_eq!(len3, 0);
    assert_eq!(&ct[0..32], &expected_ct[..]);
}

#[test]
fn save_restore_aes_cbc_enc_pkcs7() {
    let mut ct: [u8; 48] = [0; 48];
    let expected_ct: [u8; 48] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc, 0x5c, 0x04, 0x76, 0x16, 0x75, 0x6f, 0xdc, 0x1c, 0x32, 0xe0, 0xdf, 0x6e, 0x8c,
        0x59, 0xbb, 0x2a,
    ];

    let mut cipher =
        cipher::Cipher::<Encryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 128)
            .unwrap();
    cipher.set_padding(CipherPadding::Pkcs7).unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    let (len1, cipher_d1) = cipher_k.update(ZERO_16B, &mut ct[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();
    // use rustc_serialize::hex::ToHex;
    // println!("{:?}", saved.as_slice().to_hex());

    let cipher_r = de::from_slice::<Cipher<Encryption, Traditional, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(ZERO_16B, &mut ct[16..48]).unwrap();
    assert_eq!(len2, 16);

    let (len3, _) = cipher_d2.finish(&mut ct[32..48]).unwrap();
    assert_eq!(len3, 16);
    assert_eq!(&ct[..], &expected_ct[..]);
}



#[test]
fn test_openssl_decrypt() {
    use mbedtls::hash::Type as MdType;
    use mbedtls::hash::{pbkdf2_hmac};

    // All variables below are generated via script
/* 
#!/bin/bash

key=`openssl rand -base64 32` # > key.bin
salt=`xxd -u -l 8 -p /dev/urandom`
iv=`xxd -u -l 16 -p /dev/urandom`
iter=10000
openssl enc -debug -pbkdf2 -iter 10000 -aes-256-cbc -md sha256 -S $salt -in ./test.txt -out ./test.txt.enc -pass pass:$key -iv $iv

echo "let ct = [ $(cat test.txt.enc | xxd -u -p | sed -E 's/.{2}/0x&, /g') ];"
echo "let key = b\"$key\";"
echo "let iter = 10000; "
echo "let iv = [ $(echo $iv | sed -E 's/.{2}/0x&, /g') ];"
*/
    let ct = [ 0x53, 0x61, 0x6C, 0x74, 0x65, 0x64, 0x5F, 0x5F, 0xBB, 0xFF, 0x2B, 0xB1, 0x63, 0xC5, 0xA4, 0x27, 0x4A, 0xD2, 0x5C, 0x1E, 0xE0, 0x63, 0x41, 0x11, 0x4A, 0xF1, 0x9F, 0xC1, 0xB3, 0xF3, 
               0x5D, 0x4E, 0x69, 0x7F, 0x95, 0x4F, 0x00, 0x1C, 0x6E, 0x4A, 0xB4, 0x36, 0xE3, 0x36, 0xCD, 0x12, 0xD0, 0xBF,  ];
    let key = b"lawfmDi57d2RDPPgF54Y08chnOJh2eSEWu2y+RKLAqk=";
    let iter = 10000; 
    let iv = [ 0x5F, 0x63, 0xA5, 0x6D, 0x0A, 0x93, 0xE1, 0xF1, 0xDA, 0x30, 0x2F, 0x71, 0x91, 0x84, 0xFC, 0x6A,  ];
    
    // End of generated parameters
    
    // OpenSSL has a salted format where first 8 bytes are "Salted__", next 8 bytes are the salt. So check for that and extract the salt.
    if b"Salted__" != &ct[0..8] {
        panic!("File is not an openssl encrypted file using salt");
    }
    let salt = &ct[8..16];
    
    // We now derive our key via pbkdf2
    let mut derived_key = [0; 32];
    pbkdf2_hmac(MdType::Sha256, &key[..], &salt, iter, &mut derived_key).unwrap();

    // Initialize a cypher
    let mut cipher = cipher::Cipher::<Decryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 256).unwrap();

    // OpenSSL says it uses Pkcs5 by default which is equivalent to Pkcs7
    cipher.set_padding(CipherPadding::Pkcs7).unwrap();
    let cipher_k = cipher.set_key_iv(&derived_key, &iv).unwrap();

    let mut decrypted = Vec::new();

    // Allocate the length + 1 block size more to have enough space for decrypted content
    decrypted.resize(ct.len() + cipher_k.block_size(), 0);

    // Decrypt starting from byte 16 - where openSSL stores its data
    let size = cipher_k.decrypt(&ct[16..], &mut decrypted).unwrap().0;
    decrypted.resize(size, 0);

    let decrypted_string = String::from_utf8(decrypted).unwrap();

    // Double check our string matches what we encrypted
    assert_eq!("this is super secret\n", decrypted_string);
}

#[test]
fn test_openssl_encrypt() {
    use mbedtls::hash::Type as MdType;
    use mbedtls::hash::{pbkdf2_hmac};

    // All variables below are generated via script
/* 
#!/bin/bash

key=`openssl rand -base64 32` # > key.bin
salt=`xxd -u -l 8 -p /dev/urandom`
iv=`xxd -u -l 16 -p /dev/urandom`
iter=10000
openssl enc -debug -pbkdf2 -iter 10000 -aes-256-cbc -md sha256 -S $salt -in ./test.txt -out ./test.txt.enc -pass pass:$key -iv $iv

echo "let ct = [ $(cat test.txt.enc | xxd -u -p | sed -E 's/.{2}/0x&, /g') ];"
echo "let key = b\"$key\";"
echo "let iter = 10000; "
echo "let iv = [ $(echo $iv | sed -E 's/.{2}/0x&, /g') ];"
     */
    let ct = b"this is super secret\n";
    
    let key = b"lawfmDi57d2RDPPgF54Y08chnOJh2eSEWu2y+RKLAqk=";
    let iter = 10000; 
    let iv = [ 0x5F, 0x63, 0xA5, 0x6D, 0x0A, 0x93, 0xE1, 0xF1, 0xDA, 0x30, 0x2F, 0x71, 0x91, 0x84, 0xFC, 0x6A,  ];
    
    // End of generated parameters
    
    // OpenSSL has a salted format where first 8 bytes are "Salted__", next 8 bytes are the salt. So check for that and extract the salt.
    let salt = [ 0xBB, 0xFF, 0x2B, 0xB1, 0x63, 0xC5, 0xA4, 0x27 ];
    
    // We now derive our key via pbkdf2
    let mut derived_key = [0; 32];
    pbkdf2_hmac(MdType::Sha256, &key[..], &salt, iter, &mut derived_key).unwrap();

    // Initialize a cypher
    let mut cipher = cipher::Cipher::<Encryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 256).unwrap();

    // OpenSSL says it uses Pkcs5 by default which is equivalent to Pkcs7
    cipher.set_padding(CipherPadding::Pkcs7).unwrap();
    let cipher_k = cipher.set_key_iv(&derived_key, &iv).unwrap();

    let mut encrypted = Vec::new();

    // Allocate the length + 1 block size more to have enough space for decrypted content
    encrypted.resize(ct.len() + cipher_k.block_size() + 16, 0);

    // Decrypt starting from byte 16 - where openSSL stores its data
    let size = cipher_k.encrypt(&ct[..], &mut encrypted[16..]).unwrap().0;
    encrypted.resize(size+16, 0);
    encrypted[0..8].copy_from_slice(b"Salted__");
    encrypted[8..16].copy_from_slice(&salt);

    // Double check our string matches what we encrypted
    let expected = [ 0x53, 0x61, 0x6C, 0x74, 0x65, 0x64, 0x5F, 0x5F, 0xBB, 0xFF, 0x2B, 0xB1, 0x63, 0xC5, 0xA4, 0x27, 0x4A, 0xD2, 0x5C, 0x1E, 0xE0, 0x63, 0x41, 0x11, 0x4A, 0xF1, 0x9F, 0xC1, 0xB3, 0xF3, 
                     0x5D, 0x4E, 0x69, 0x7F, 0x95, 0x4F, 0x00, 0x1C, 0x6E, 0x4A, 0xB4, 0x36, 0xE3, 0x36, 0xCD, 0x12, 0xD0, 0xBF,  ];

    assert_eq!(expected, encrypted.as_slice());
}


#[test]
fn save_restore_aes_cbc_dec_nopad() {
    let mut pt: [u8; 48] = [0; 48];
    let ct: [u8; 32] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc,
    ];

    let mut cipher =
        cipher::Cipher::<Decryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 128)
            .unwrap();
    cipher.set_padding(CipherPadding::None).unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    // For decryption without padding, you can get the data right away, *if* you
    // use Fortanix's patched mbedtls.
    let (len1, cipher_d1) = cipher_k.update(&ct[0..16], &mut pt[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();
    // use rustc_serialize::hex::ToHex;
    // println!("{:?}", saved.as_slice().to_hex());

    let cipher_r = de::from_slice::<Cipher<Decryption, Traditional, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(&ct[16..32], &mut pt[16..48]).unwrap();
    assert_eq!(len2, 16);

    let (len3, _) = cipher_d2.finish(&mut pt[32..48]).unwrap();
    assert_eq!(len3, 0);
    assert_eq!(&pt[0..16], ZERO_16B);
    assert_eq!(&pt[16..32], ZERO_16B);
}

#[test]
fn save_restore_aes_cbc_dec_pkcs7() {
    let mut pt: [u8; 48] = [0; 48];
    let ct: [u8; 48] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc, 0x5c, 0x04, 0x76, 0x16, 0x75, 0x6f, 0xdc, 0x1c, 0x32, 0xe0, 0xdf, 0x6e, 0x8c,
        0x59, 0xbb, 0x2a,
    ];

    let mut cipher =
        cipher::Cipher::<Decryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 128)
            .unwrap();
    cipher.set_padding(CipherPadding::Pkcs7).unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    // For decryption with padding, mbedtls keeps the last block until we do `finish()`
    let (len1, cipher_d1) = cipher_k.update(&ct[0..16], &mut pt[0..32]).unwrap();
    assert_eq!(len1, 0);

    let saved = ser::to_vec(&cipher_d1).unwrap();
    // use rustc_serialize::hex::ToHex;
    // println!("{:?}", saved.as_slice().to_hex());

    let cipher_r = de::from_slice::<Cipher<Decryption, Traditional, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(&ct[16..48], &mut pt[0..48]).unwrap();
    assert_eq!(len2, 32);

    let (len3, _) = cipher_d2.finish(&mut pt[32..48]).unwrap();
    assert_eq!(len3, 0);
    assert_eq!(&pt[0..16], ZERO_16B);
    assert_eq!(&pt[16..32], ZERO_16B);
}

#[test]
fn save_restore_wrong_type() {
    let mut ct: [u8; 48] = [0; 48];

    let cipher =
        cipher::Cipher::<Encryption, Traditional, Fresh>::new(CipherId::Aes, CipherMode::CBC, 128)
            .unwrap();
    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    let (len1, cipher_d1) = cipher_k.update(ZERO_16B, &mut ct[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();

    // Try to restore the saved encrypt state as a decrypt
    de::from_slice::<Cipher<Decryption, Traditional, _>>(saved.as_slice())
        .err()
        .expect("shouldn't have been able to deserialize with wrong operation");
}

#[test]
fn save_restore_aes_gcm_enc() {
    let mut ct: [u8; 48] = [0; 48];
    let expected_ct: [u8; 32] = [
        0xa3, 0xb2, 0x2b, 0x84, 0x49, 0xaf, 0xaf, 0xbc, 0xd6, 0xc0, 0x9f, 0x2c, 0xfa, 0x9d, 0xe2,
        0xbe, 0x93, 0x8f, 0x8b, 0xbf, 0x23, 0x58, 0x63, 0xd0, 0xce, 0x02, 0x84, 0x27, 0x22, 0xfd,
        0x50, 0x34
    ];

    let mut tag: [u8; 8] = [0; 8];
    let expected_tag: [u8; 8] = [0x2a, 0x71, 0x95, 0xb4, 0x4b, 0xf6, 0x3c, 0x2d];

    let cipher =
        cipher::Cipher::<Encryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, 128)
            .unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    let cipher_a = cipher_k.set_ad(ZERO_16B).unwrap();

    let (len1, cipher_d1) = cipher_a.update(ZERO_16B, &mut ct[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();

    let cipher_r = de::from_slice::<Cipher<Encryption, Authenticated, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(ZERO_16B, &mut ct[16..48]).unwrap();
    assert_eq!(len2, 16);

    let (len3, cipher_f) = cipher_d2.finish(&mut ct[32..48]).unwrap();

    cipher_f.write_tag(&mut tag).unwrap();

    assert_eq!(len3, 0);
    assert_eq!(&ct[0..32], &expected_ct[..]);
    assert_eq!(tag, expected_tag);
}

#[test]
fn save_restore_aes_gcm_dec() {
    let mut pt: [u8; 48] = [0; 48];
    let ct: [u8; 32] =  [
        0xa3, 0xb2, 0x2b, 0x84, 0x49, 0xaf, 0xaf, 0xbc, 0xd6, 0xc0, 0x9f, 0x2c, 0xfa, 0x9d, 0xe2,
        0xbe, 0x93, 0x8f, 0x8b, 0xbf, 0x23, 0x58, 0x63, 0xd0, 0xce, 0x02, 0x84, 0x27, 0x22, 0xfd,
        0x50, 0x34
    ];
    let tag: [u8; 8] = [ 0x2a, 0x71, 0x95, 0xb4, 0x4b, 0xf6, 0x3c, 0x2d ];

    let cipher =
        cipher::Cipher::<Decryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, 128)
            .unwrap();

    let cipher_k = cipher.set_key_iv(ZERO_16B, ZERO_16B).unwrap();

    let cipher_a = cipher_k.set_ad(ZERO_16B).unwrap();

    let (len1, cipher_d1) = cipher_a.update(&ct[0..16], &mut pt[0..32]).unwrap();
    assert_eq!(len1, 16);

    let saved = ser::to_vec(&cipher_d1).unwrap();

    let cipher_r = de::from_slice::<Cipher<Decryption, Authenticated, _>>(saved.as_slice()).unwrap();

    let (len2, cipher_d2) = cipher_r.update(&ct[16..32], &mut pt[16..48]).unwrap();
    assert_eq!(len2, 16);

    let (len3, cipher_f) = cipher_d2.finish(&mut pt[32..48]).unwrap();

    cipher_f.check_tag(&tag).unwrap();

    assert_eq!(len3, 0);
    assert_eq!(&pt[0..16], ZERO_16B);
    assert_eq!(&pt[16..32], ZERO_16B);
}
