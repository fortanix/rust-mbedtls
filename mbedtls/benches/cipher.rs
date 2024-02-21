use std::time::Duration;

use criterion::{black_box, criterion_main, Criterion};
use mbedtls::cipher::{raw, Authenticated, Cipher, Traditional};

pub fn criterion_benchmark(criterion: &mut Criterion) {
    // AES CBC
    let key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];
    let plain_text = [
        0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea, 0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed, 0x3f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let iv = [0u8; 16];
    let out_len = 32;
    let cipher_mode = raw::CipherMode::CBC;
    let cipher_out = aes_encrypt(&key, &iv, &plain_text[..16], cipher_mode, out_len);
    // criterion.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
    //     b.iter(|| aes_encrypt(&key, &iv, &plain_text[..16], cipher_mode, out_len))
    // });
    criterion.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt(&key, &iv, &cipher_out, &plain_text, cipher_mode))
    });

    // variables for AES CCM & GCM
    let key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];
    let plain_text = [0x20, 0x21, 0x22, 0x23];
    let iv = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let ad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let tag_len = 4;
    let out_len = plain_text.len() + tag_len;

    // AES CCM
    let cipher_mode = raw::CipherMode::CCM;
    let cipher_and_tag = aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, out_len);
    criterion.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| aes_encrypt_auth(&key, &iv, &ad, black_box(&plain_text), cipher_mode, tag_len, out_len))
    });
    criterion.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt_auth(&key, &iv, &ad, black_box(&cipher_and_tag), &plain_text, cipher_mode, tag_len))
    });

    // AES GCM
    let cipher_mode = raw::CipherMode::GCM;
    let cipher_and_tag = aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, out_len);
    criterion.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| aes_encrypt_auth(&key, &iv, &ad, black_box(&plain_text), cipher_mode, tag_len, out_len))
    });
    criterion.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt_auth(&key, &iv, &ad, black_box(&cipher_and_tag), &plain_text, cipher_mode, tag_len))
    });

    // AES KW
    let key = [
        0x75, 0x75, 0xda, 0x3a, 0x93, 0x60, 0x7c, 0xc2, 0xbf, 0xd8, 0xce, 0xc7, 0xaa, 0xdf, 0xd9, 0xa6,
    ];
    let plain_text = [
        0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea, 0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed, 0x3f,
    ];
    let iv = [0u8; 0];
    let ad = [0u8; 0];
    let tag_len = 0;
    let out_len = 24;
    let cipher_mode = raw::CipherMode::KW;
    let cipher_and_tag = aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, out_len);
    criterion.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| aes_encrypt_auth(&key, &iv, &ad, black_box(&plain_text), cipher_mode, tag_len, out_len))
    });
    criterion.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt_auth(&key, &iv, &ad, black_box(&cipher_and_tag), &plain_text, cipher_mode, tag_len))
    });

    // AES KWP
    let key = [
        0x78, 0x65, 0xe2, 0x0f, 0x3c, 0x21, 0x65, 0x9a, 0xb4, 0x69, 0x0b, 0x62, 0x9c, 0xdf, 0x3c, 0xc4,
    ];
    let plain_text = [
        0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea, 0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed, 0x3f,
    ];
    let iv = [0u8; 0];
    let ad = [0u8; 0];
    let tag_len = 0;
    let out_len = 24;
    let cipher_mode = raw::CipherMode::KWP;
    let cipher_and_tag = aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, out_len);
    criterion.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| aes_encrypt_auth(&key, &iv, &ad, black_box(&plain_text), cipher_mode, tag_len, out_len))
    });
    criterion.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt_auth(&key, &iv, &ad, black_box(&cipher_and_tag), &plain_text, cipher_mode, tag_len))
    });
}

fn aes_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
    cipher_and_tag: &[u8],
    expected_plain: &[u8],
    cipher_mode: raw::CipherMode,
    tag_len: usize,
) -> Vec<u8> {
    let mut plain_out = vec![0u8; expected_plain.len()];
    let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.decrypt_auth(ad, cipher_and_tag, &mut plain_out, tag_len).unwrap();
    assert_eq!(*expected_plain, plain_out);
    plain_out
}

fn aes_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
    plain_text: &[u8],
    cipher_mode: raw::CipherMode,
    tag_len: usize,
    out_len: usize,
) -> Vec<u8> {
    let mut cipher_and_tag_out = vec![0u8; out_len];
    let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.encrypt_auth(ad, plain_text, &mut cipher_and_tag_out, tag_len).unwrap();
    cipher_and_tag_out
}

fn aes_decrypt(key: &[u8], iv: &[u8], cipher_text: &[u8], expected_plain: &[u8], cipher_mode: raw::CipherMode) -> Vec<u8> {
    let mut plain_out = vec![0u8; expected_plain.len()];
    let cipher = Cipher::<_, Traditional, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    let res = cipher.decrypt(cipher_text, &mut plain_out).unwrap();
    assert_eq!(expected_plain[..res.0], plain_out[..res.0]);
    plain_out
}

fn aes_encrypt(key: &[u8], iv: &[u8], plain_text: &[u8], cipher_mode: raw::CipherMode, out_len: usize) -> Vec<u8> {
    let mut cipher_out = vec![0u8; out_len];
    let cipher = Cipher::<_, Traditional, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.encrypt(plain_text, &mut cipher_out).unwrap();
    cipher_out
}

pub fn benches() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(10))
        .measurement_time(Duration::from_secs(30))
        .sample_size(10_000)
        .configure_from_args();
    criterion_benchmark(&mut criterion);
}
criterion_main!(benches);
