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
use std::sync::Arc;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, Version};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod support;
use support::entropy::entropy_new;
use support::keys;
use tokio::net::TcpStream;

// TODO: Add unified interface for TCP and UDP like `TransportType` in
// `client_server.rs`

async fn client(conn: TcpStream, min_version: Version, max_version: Version, exp_version: Option<Version>) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes())?);
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
                                                            //so removing this flag here prevents the connections from failing with
                                                            // VerifyError
            Ok(())
        };
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_verify_callback(verify_callback);
        config.set_ca_list(cacert, None);
        config.set_min_version(min_version)?;
        config.set_max_version(max_version)?;
        let mut ctx = Context::new(Arc::new(config));

        match ctx.establish_async(conn, None).await {
            Ok(()) => {
                assert_eq!(ctx.version(), exp_version.unwrap());
            }
            Err(e) => {
                match e {
                    Error::SslBadHsProtocolVersion => {
                        assert!(exp_version.is_none())
                    }
                    Error::SslFatalAlertMessage => {}
                    e => panic!("Unexpected error {}", e),
                };
                return Ok(());
            }
        };

        let ciphersuite = ctx.ciphersuite().unwrap();
        ctx.write_all(format!("Client2Server {:4x}", ciphersuite).as_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; 13 + 4 + 1];
        ctx.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    } // drop verify_callback, releasing borrow of verify_args
    Ok(())
}

async fn server(conn: TcpStream, min_version: Version, max_version: Version, exp_version: Option<Version>) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes())?);
    let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY.as_bytes(), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    config.push_cert(cert, key)?;
    let mut context = Context::new(Arc::new(config));

    match context.establish_async(conn, None).await {
        Ok(()) => {
            assert_eq!(context.version(), exp_version.unwrap());
        }
        Err(e) => {
            match e {
                // client just closes connection instead of sending alert
                Error::NetSendFailed => {
                    assert!(exp_version.is_none())
                }
                Error::SslBadHsProtocolVersion => {}
                e => panic!("Unexpected error {}", e),
            };
            return Ok(());
        }
    };

    //assert_eq!(ctx.get_alpn_protocol().unwrap().unwrap(), None);
    let ciphersuite = context.ciphersuite().unwrap();
    context
        .write_all(format!("Server2Client {:4x}", ciphersuite).as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 13 + 1 + 4];
    context.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, format!("Client2Server {:4x}", ciphersuite).as_bytes());
    Ok(())
}

async fn with_client<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> Pin<Box<dyn Future<Output = R> + Send>>,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes()).unwrap());

    let verify_callback = move |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
        verify_flags.remove(VerifyError::CERT_EXPIRED);
        Ok(())
    };

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_verify_callback(verify_callback);
    config.set_ca_list(cacert, None);
    let mut context = Context::new(Arc::new(config));

    context.establish_async(conn, None).await.unwrap();

    f(context).await
}

async fn with_server<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> Pin<Box<dyn Future<Output = R> + Send>>,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes()).unwrap());
    let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY.as_bytes(), None).unwrap());

    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key).unwrap();
    let mut context = Context::new(Arc::new(config));

    context.establish_async(conn, None).await.unwrap();

    f(context).await
}

#[cfg(unix)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn async_session_client_server_test() {
        use mbedtls::ssl::Version;

        #[derive(Copy, Clone)]
        struct TestConfig {
            min_c: Version,
            max_c: Version,
            min_s: Version,
            max_s: Version,
            exp_ver: Option<Version>,
        }

        impl TestConfig {
            pub fn new(min_c: Version, max_c: Version, min_s: Version, max_s: Version, exp_ver: Option<Version>) -> Self {
                TestConfig {
                    min_c,
                    max_c,
                    min_s,
                    max_s,
                    exp_ver,
                }
            }
        }

        let test_configs = [
            TestConfig::new(
                Version::Ssl3,
                Version::Ssl3,
                Version::Ssl3,
                Version::Ssl3,
                Some(Version::Ssl3),
            ),
            TestConfig::new(
                Version::Ssl3,
                Version::Tls1_2,
                Version::Ssl3,
                Version::Ssl3,
                Some(Version::Ssl3),
            ),
            TestConfig::new(
                Version::Tls1_0,
                Version::Tls1_0,
                Version::Tls1_0,
                Version::Tls1_0,
                Some(Version::Tls1_0),
            ),
            TestConfig::new(
                Version::Tls1_1,
                Version::Tls1_1,
                Version::Tls1_1,
                Version::Tls1_1,
                Some(Version::Tls1_1),
            ),
            TestConfig::new(
                Version::Tls1_2,
                Version::Tls1_2,
                Version::Tls1_2,
                Version::Tls1_2,
                Some(Version::Tls1_2),
            ),
            TestConfig::new(
                Version::Tls1_0,
                Version::Tls1_2,
                Version::Tls1_0,
                Version::Tls1_2,
                Some(Version::Tls1_2),
            ),
            TestConfig::new(
                Version::Tls1_2,
                Version::Tls1_2,
                Version::Tls1_0,
                Version::Tls1_2,
                Some(Version::Tls1_2),
            ),
            TestConfig::new(Version::Tls1_0, Version::Tls1_1, Version::Tls1_2, Version::Tls1_2, None),
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
    async fn async_session_shutdown1() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |mut session| {
            Box::pin(async move {
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, |mut session| {
            Box::pin(async move {
                let mut buf = [0u8; 1];
                match session.read(&mut buf).await {
                    Ok(0) | Err(_) => {}
                    _ => panic!("expected no data"),
                }
            })
        }));

        c.await.unwrap();
        s.await.unwrap();
    }

    #[tokio::test]
    async fn async_session_shutdown2() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |mut session| {
            Box::pin(async move {
                let mut buf = [0u8; 5];
                session.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");
                match session.read(&mut buf).await {
                    Ok(0) | Err(_) => {}
                    _ => panic!("expected no data"),
                }
            })
        }));

        let s = tokio::spawn(super::with_server(s, |mut session| {
            Box::pin(async move {
                session.write_all(b"hello").await.unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        c.await.unwrap();
        s.await.unwrap();
    }

    #[tokio::test]
    async fn async_session_shutdown3() {
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();

        let c = tokio::spawn(super::with_client(c, |mut session| {
            Box::pin(async move { session.shutdown().await })
        }));

        let s = tokio::spawn(super::with_server(s, |mut session| {
            Box::pin(async move { session.shutdown().await })
        }));

        match (c.await.unwrap(), s.await.unwrap()) {
            (Err(_), Err(_)) => panic!("at least one should succeed"),
            _ => {}
        }
    }

    #[tokio::test]
    async fn test_write_tracker() {
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        const BUFFER_SIZE: usize = 3 * 1024 * 1024;
        let expected_data = random_data(BUFFER_SIZE);
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);

        let (c, s) = crate::support::net::create_tcp_stream_pair_loopback_async();
        let c = tokio::spawn(super::with_client(c, |mut session| {
            Box::pin(async move {
                eprintln!("client write_all {} bytes", BUFFER_SIZE);
                session.write_all(&data_to_write).await.unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, |mut session| {
            Box::pin(async move {
                let mut buf = vec![0; BUFFER_SIZE];
                match session.read_exact(&mut buf).await {
                    Ok(n) => {
                        eprintln!("server read {}", n);
                        assert_eq!(n, BUFFER_SIZE, "wrong length");
                        assert!(&buf[..] == &expected_data[..], "wrong read data");
                        return;
                    }
                    Err(e) => {
                        session.shutdown().await.unwrap();
                        panic!("Unexpected error {:?}", e);
                    }
                }
            })
        }));

        c.await.unwrap();
        s.await.unwrap();
    }

    fn random_data(sz: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut data: Vec<u8> = Vec::with_capacity(sz);

        for _ in 0..sz {
            data.push(rng.gen_range(0, 255));
        }

        data
    }
}
