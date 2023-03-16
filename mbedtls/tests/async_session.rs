/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

extern crate mbedtls;

use std::future::Future;
use std::pin::Pin;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, IoAdapter, AsyncSession, Version};
use mbedtls::x509::{Certificate, LinkedCertificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod support;
use support::entropy::entropy_new;
use support::keys;

async fn client(
    conn: TcpStream,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cacert = Certificate::from_pem(keys::ROOT_CA_CERT)?;
    let expected_flags = VerifyError::empty();
    #[cfg(feature = "time")]
    let expected_flags = expected_flags | VerifyError::CERT_EXPIRED;
    let mut verify_args = None;
    {
        let verify_callback =
            &mut |crt: &mut LinkedCertificate, depth, verify_flags: &mut VerifyError| {
                verify_args = Some((crt.subject().unwrap(), depth, *verify_flags));
                verify_flags.remove(VerifyError::CERT_EXPIRED); //we check the flags at the end,
                //so removing this flag here prevents the connections from failing with VerifyError
                Ok(())
            };
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng));
        config.set_verify_callback(verify_callback);
        config.set_ca_list(Some(&mut *cacert), None);
        config.set_min_version(min_version)?;
        config.set_max_version(max_version)?;
        let mut ctx = Context::new(&config)?;
        let mut conn = IoAdapter::new(conn);

        let session = ctx.establish_async(&mut conn, None).await;

        let mut session = match session {
            Ok(s) => {
                assert_eq!(s.version().unwrap(), exp_version.unwrap());
                s
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

        let ciphersuite = session.ciphersuite().unwrap();
        session
            .write_all(format!("Client2Server {:4x}", ciphersuite).as_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; 13 + 4 + 1];
        session.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    } // drop verify_callback, releasing borrow of verify_args
    assert_eq!(verify_args, Some((keys::EXPIRED_CERT_SUBJECT.to_owned(), 0, expected_flags)));
    Ok(())
}

async fn server(
    conn: TcpStream,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::EXPIRED_CERT)?;
    let mut key = Pk::from_private_key(keys::EXPIRED_KEY, None)?;
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    config.push_cert(&mut *cert, &mut key)?;
    let mut ctx = Context::new(&config)?;
    let mut conn = IoAdapter::new(conn);

    let session = ctx.establish_async(&mut conn, None).await;
    let mut session = match session {
        Ok(s) => {
            assert_eq!(s.version().unwrap(), exp_version.unwrap());
            s
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

    assert_eq!(session.get_alpn_protocol().unwrap().unwrap(), None);
    let ciphersuite = session.ciphersuite().unwrap();
    session
        .write_all(format!("Server2Client {:4x}", ciphersuite).as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 13 + 1 + 4];
    session.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, format!("Client2Server {:4x}", ciphersuite).as_bytes());
    Ok(())
}

async fn with_client<F, R>(conn: TcpStream, f: F) -> R
where
    F: for <'a, 'b> FnOnce(&'a mut AsyncSession<'b>) -> Pin<Box<dyn Future<Output = R> + Send + 'a>>,
{
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();
    let mut cacert = Certificate::from_pem(keys::ROOT_CA_CERT).unwrap();
    let verify_callback = &mut |_crt: &mut LinkedCertificate, _depth, verify_flags: &mut VerifyError| {
        verify_flags.remove(VerifyError::CERT_EXPIRED);
        Ok(())
    };
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_verify_callback(verify_callback);
    config.set_ca_list(Some(&mut *cacert), None);
    let mut ctx = Context::new(&config).unwrap();
    let mut conn = IoAdapter::new(conn);
    let mut session = ctx.establish_async(&mut conn, None).await.unwrap();

    f(&mut session).await
}

async fn with_server<F, R>(conn: TcpStream, f: F) -> R
where
    F: for <'a, 'b> FnOnce(&'a mut AsyncSession<'b>) -> Pin<Box<dyn Future<Output = R> + Send + 'a>>,
{
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();
    let mut cert = Certificate::from_pem(keys::EXPIRED_CERT).unwrap();
    let mut key = Pk::from_private_key(keys::EXPIRED_KEY, None).unwrap();
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.push_cert(&mut *cert, &mut key).unwrap();
    let mut ctx = Context::new(&config).unwrap();
    let mut conn = IoAdapter::new(conn);
    let mut session = ctx.establish_async(&mut conn, None).await.unwrap();

    f(&mut session).await
}

#[cfg(unix)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_server_test() {
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

            let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
            let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver.clone()));
            let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver));

            c.await.unwrap().unwrap();
            s.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown1() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |session| Box::pin(async move {
            session.shutdown().await.unwrap();
        })));

        let s = tokio::spawn(super::with_server(s, |session| Box::pin(async move {
            let mut buf = [0u8; 1];
            match session.read(&mut buf).await {
                Ok(0) | Err(_) => {}
                _ => panic!("expected no data"),
            }
        })));

        c.await.unwrap();
        s.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown2() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |session| Box::pin(async move {
            let mut buf = [0u8; 5];
            session.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            match session.read(&mut buf).await {
                Ok(0) | Err(_) => {}
                _ => panic!("expected no data"),
            }
        })));

        let s = tokio::spawn(super::with_server(s, |session| Box::pin(async move {
            session.write_all(b"hello").await.unwrap();
            session.shutdown().await.unwrap();
        })));

        c.await.unwrap();
        s.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown3() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |session| Box::pin(async move {
            session.shutdown().await
        })));

        let s = tokio::spawn(super::with_server(s, |session| Box::pin(async move {
            session.shutdown().await
        })));

        match (c.await.unwrap(), s.await.unwrap()) {
            (Err(_), Err(_)) => panic!("at least one should succeed"),
            _ => {}
        }
    }
}
