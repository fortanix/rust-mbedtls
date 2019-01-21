extern crate mbedtls;

use mbedtls::hash::{Md, Type as MdType};
use mbedtls::pk::Type as PkType;
use mbedtls::x509::certificate::Certificate;

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
fn certificate() {
    let cert = Certificate::from_pem(&TEST_CERT_PEM.as_bytes()).unwrap();

    assert_eq!(cert.issuer().unwrap(), "CN=Test CA, C=US");
    assert_eq!(cert.subject().unwrap(), "CN=Test Cert, O=Test");
    assert_eq!(
        cert.serial().unwrap(),
        "B6:34:49:2E:69:63:D6:1B:FD:A2:07:BD:20:2F:98:EB"
    );
    assert_eq!(cert.digest_type(), MdType::Sha256);

    let pk = cert.public_key();

    assert_eq!(pk.pk_type(), PkType::Rsa);
    assert_eq!(pk.rsa_public_exponent().unwrap(), 0x10001);

    let channel_binding_hash = match cert.digest_type() {
        MdType::Md5 | MdType::Sha1 => MdType::Sha256,
        digest => digest,
    };

    let mut digest = [0u8; 64];
    let digest_len = Md::hash(channel_binding_hash, cert.as_der(), &mut digest).unwrap();

    assert_eq!(
        digest[0..digest_len],
        [
            0xcc, 0x61, 0xd9, 0x07, 0xc2, 0xcb, 0x49, 0x58, 0x73, 0xbf, 0xd7, 0x43, 0x21, 0xb2,
            0xd4, 0x30, 0xc6, 0xfe, 0xa6, 0x6c, 0x28, 0x96, 0x23, 0xc6, 0x28, 0x4c, 0xdd, 0x14,
            0xda, 0x1d, 0xc4, 0x17
        ]
    );
}
