use std::time::Duration;

use criterion::{black_box, criterion_main, Criterion};
use mbedtls::cipher::{raw, Authenticated, Cipher};

pub fn criterion_benchmark(criterion: &mut Criterion) {
    // variables for AES CCM
    let key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];
    let iv = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let ad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let plain_text = [0x20, 0x21, 0x22, 0x23];
    // let mut p_out = [0u8; 4];
    let expected_cipher = [0x71, 0x62, 0x01, 0x5b];
    let expected_tag = [0x4d, 0xac, 0x25, 0x5d];

    criterion.bench_function("AES CCM encrypt", |b| {
        b.iter(|| aes_ccm_encrypt(&key, &iv, &ad, black_box(&plain_text), &expected_cipher, &expected_tag))
    });
}

fn aes_ccm_encrypt(
    key: &[u8; 16],
    iv: &[u8; 7],
    ad: &[u8; 8],
    plain_text: &[u8; 4],
    expected_cipher: &[u8; 4],
    expected_tag: &[u8; 4],
) {
    let mut cipher_and_tag_out = [0u8; 8];
    let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::CCM, (key.len() * 8) as _).unwrap();
    let cipher = cipher.set_key_iv(key, iv).unwrap();
    cipher.encrypt_auth(ad, plain_text, &mut cipher_and_tag_out, 4).unwrap();
    assert_eq!(*expected_cipher, cipher_and_tag_out[0..4]);
    assert_eq!(*expected_tag, cipher_and_tag_out[4..8]);
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
