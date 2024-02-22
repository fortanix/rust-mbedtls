use criterion::{black_box, criterion_main, Criterion};
use mbedtls::cipher::{raw, Authenticated, Cipher, Traditional};

pub fn cipher(criterion: &mut Criterion) {
    let mut cipher_bench_group = criterion.benchmark_group("Cipher");
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
    let mut cipher_out = vec![0u8; out_len];
    aes_encrypt(&key, &iv, &plain_text[..16], cipher_mode, &mut cipher_out);
    let mut cipher_out_tmp = vec![0u8; out_len];
    let mut plain_out_tmp = vec![0u8; plain_text.len()];
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| aes_encrypt(&key, &iv, black_box(&plain_text[..16]), cipher_mode, &mut cipher_out_tmp))
    });
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| aes_decrypt(&key, &iv, black_box(&cipher_out), cipher_mode, &mut plain_out_tmp))
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
    let mut cipher_and_tag_out = vec![0u8; out_len];
    let mut cipher_and_tag_out_tmp = vec![0u8; out_len];
    let mut plain_out = vec![0u8; plain_text.len()];
    aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, &mut cipher_and_tag_out);
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| {
            aes_encrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&plain_text),
                cipher_mode,
                tag_len,
                &mut cipher_and_tag_out_tmp,
            )
        })
    });
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| {
            aes_decrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&cipher_and_tag_out),
                cipher_mode,
                tag_len,
                &mut plain_out,
            )
        })
    });

    // AES GCM
    let cipher_mode = raw::CipherMode::GCM;
    let mut cipher_and_tag_out = vec![0u8; out_len];
    let mut cipher_and_tag_out_tmp = vec![0u8; out_len];
    let mut plain_out = vec![0u8; plain_text.len()];
    aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, &mut cipher_and_tag_out);
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| {
            aes_encrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&plain_text),
                cipher_mode,
                tag_len,
                &mut cipher_and_tag_out_tmp,
            )
        })
    });
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| {
            aes_decrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&cipher_and_tag_out),
                cipher_mode,
                tag_len,
                &mut plain_out,
            )
        })
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
    let mut cipher_and_tag_out = vec![0u8; out_len];
    let mut cipher_and_tag_out_tmp = vec![0u8; out_len];
    let mut plain_out = vec![0u8; plain_text.len()];
    aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, &mut cipher_and_tag_out);
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| {
            aes_encrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&plain_text),
                cipher_mode,
                tag_len,
                &mut cipher_and_tag_out_tmp,
            )
        })
    });
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| {
            aes_decrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&cipher_and_tag_out),
                cipher_mode,
                tag_len,
                &mut plain_out,
            )
        })
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
    let mut cipher_and_tag_out = vec![0u8; out_len];
    let mut cipher_and_tag_out_tmp = vec![0u8; out_len];
    let mut plain_out = vec![0u8; plain_text.len()];
    aes_encrypt_auth(&key, &iv, &ad, &plain_text, cipher_mode, tag_len, &mut cipher_and_tag_out);
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} encrypt"), |b| {
        b.iter(|| {
            aes_encrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&plain_text),
                cipher_mode,
                tag_len,
                &mut cipher_and_tag_out_tmp,
            )
        })
    });
    cipher_bench_group.bench_function(&format!("AES {cipher_mode:?} decrypt"), |b| {
        b.iter(|| {
            aes_decrypt_auth(
                &key,
                &iv,
                &ad,
                black_box(&cipher_and_tag_out),
                cipher_mode,
                tag_len,
                &mut plain_out,
            )
        })
    });
}

fn aes_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
    cipher_and_tag: &[u8],
    cipher_mode: raw::CipherMode,
    tag_len: usize,
    plain_out: &mut [u8],
) {
    let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.decrypt_auth(ad, cipher_and_tag, plain_out, tag_len).unwrap();
}

fn aes_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
    plain_text: &[u8],
    cipher_mode: raw::CipherMode,
    tag_len: usize,
    cipher_and_tag_out: &mut [u8],
) {
    let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.encrypt_auth(ad, plain_text, cipher_and_tag_out, tag_len).unwrap();
}

fn aes_decrypt(key: &[u8], iv: &[u8], cipher_text: &[u8], cipher_mode: raw::CipherMode, plain_out: &mut [u8]) {
    let cipher = Cipher::<_, Traditional, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.decrypt(cipher_text, plain_out).unwrap();
}

fn aes_encrypt(key: &[u8], iv: &[u8], plain_text: &[u8], cipher_mode: raw::CipherMode, cipher_out: &mut [u8]) {
    let cipher = Cipher::<_, Traditional, _>::new(raw::CipherId::Aes, cipher_mode, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.encrypt(plain_text, cipher_out).unwrap();
}

pub fn benches() {
    let mut criterion = Criterion::default()
        .sample_size(1000)
        .configure_from_args();
    cipher(&mut criterion);
}
criterion_main!(benches);
