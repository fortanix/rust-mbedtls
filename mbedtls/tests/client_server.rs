/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

extern crate mbedtls;

use std::io::{Read, Write};
use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, Version};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;
use std::sync::Arc;

mod support;
use support::entropy::entropy_new;
use support::keys;

fn client(
    conn: TcpStream,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT)?);
    let expected_flags = VerifyError::empty();
    #[cfg(feature = "time")]
    let expected_flags = expected_flags | VerifyError::CERT_EXPIRED;
    {
        let verify_callback = move |crt: &Certificate, depth: i32, verify_flags: &mut VerifyError| {

            match (crt.subject().unwrap().as_str(), depth, &verify_flags) {
                ("CN=RootCA", 1, _) => (),
                (keys::EXPIRED_CERT_SUBJECT, 0, flags) => assert_eq!(**flags, expected_flags),
                _ => assert!(false),
            };
            
            verify_flags.remove(VerifyError::CERT_EXPIRED); //we check the flags at the end,
            //so removing this flag here prevents the connections from failing with VerifyError
            Ok(())
        };
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_verify_callback(verify_callback);
        config.set_ca_list(cacert, None);
        config.set_min_version(min_version)?;
        config.set_max_version(max_version)?;
        let mut ctx = Context::new(Arc::new(config));

        match ctx.establish(conn, None) {
            Ok(()) => {
                assert_eq!(ctx.version(), exp_version.unwrap());
            }
            Err(e) => {
                match e {
                    Error::SslBadHsProtocolVersion => {assert!(exp_version.is_none())},
                    Error::SslFatalAlertMessage => {},
                    e => panic!("Unexpected error {}", e),
                };
                return Ok(());
            }
        };

        let ciphersuite = ctx.ciphersuite().unwrap();
        ctx.write_all(format!("Client2Server {:4x}", ciphersuite).as_bytes()).unwrap();
        let mut buf = [0u8; 13 + 4 + 1];
        ctx.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    }
    Ok(())
}

fn server(
    conn: TcpStream,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT)?);
    let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY, None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    config.push_cert(cert, key)?;
    let mut ctx = Context::new(Arc::new(config));

    match ctx.establish(conn, None) {
        Ok(()) => {
            assert_eq!(ctx.version(), exp_version.unwrap());
        }
        Err(e) => {
            match e {
                // client just closes connection instead of sending alert
                Error::NetSendFailed => {assert!(exp_version.is_none())},
                Error::SslBadHsProtocolVersion => {},
                e => panic!("Unexpected error {}", e),
            };
            return Ok(());
        }
    };

    let ciphersuite = ctx.ciphersuite().unwrap();
    ctx.write_all(format!("Server2Client {:4x}", ciphersuite).as_bytes()).unwrap();
    let mut buf = [0u8; 13 + 1 + 4];
    ctx.read_exact(&mut buf).unwrap();

    assert_eq!(&buf, format!("Client2Server {:4x}", ciphersuite).as_bytes());
    Ok(())
}

#[cfg(unix)]
mod test {
    use std::thread;

    #[test]
    fn client_server_test() {
        use mbedtls::ssl::Version;

        #[derive(Copy,Clone)]
        struct TestConfig {
            min_c: Version,
            max_c: Version,
            min_s: Version,
            max_s: Version,
            exp_ver: Option<Version>,
        }

        impl TestConfig {
            pub fn new(min_c: Version, max_c: Version, min_s: Version, max_s: Version, exp_ver: Option<Version>) -> Self {
                TestConfig { min_c, max_c, min_s, max_s, exp_ver }
            }
        }

        let test_configs = [
            TestConfig::new(Version::Ssl3, Version::Ssl3, Version::Ssl3, Version::Ssl3, Some(Version::Ssl3)),
            TestConfig::new(Version::Ssl3, Version::Tls1_2, Version::Ssl3, Version::Ssl3, Some(Version::Ssl3)),
            TestConfig::new(Version::Tls1_0, Version::Tls1_0, Version::Tls1_0, Version::Tls1_0, Some(Version::Tls1_0)),
            TestConfig::new(Version::Tls1_1, Version::Tls1_1, Version::Tls1_1, Version::Tls1_1, Some(Version::Tls1_1)),
            TestConfig::new(Version::Tls1_2, Version::Tls1_2, Version::Tls1_2, Version::Tls1_2, Some(Version::Tls1_2)),
            TestConfig::new(Version::Tls1_0, Version::Tls1_2, Version::Tls1_0, Version::Tls1_2, Some(Version::Tls1_2)),
            TestConfig::new(Version::Tls1_2, Version::Tls1_2, Version::Tls1_0, Version::Tls1_2, Some(Version::Tls1_2)),
            TestConfig::new(Version::Tls1_0, Version::Tls1_1, Version::Tls1_2, Version::Tls1_2, None)
        ];

        for config in &test_configs {
            let min_c = config.min_c;
            let max_c = config.max_c;
            let min_s = config.min_s;
            let max_s = config.max_s;
            let exp_ver = config.exp_ver;

            if (max_c < Version::Tls1_2 || max_s < Version::Tls1_2) && !cfg!(feature = "legacy_protocols") {
                continue;
            }

            let (c, s) = crate::support::net::create_tcp_pair().unwrap();
            let c = thread::spawn(move || super::client(c, min_c, max_c, exp_ver.clone()).unwrap());
            let s = thread::spawn(move || super::server(s, min_s, max_s, exp_ver).unwrap());

            c.join().unwrap();
            s.join().unwrap();
        }
    }
}
