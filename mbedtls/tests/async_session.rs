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
use mbedtls::error::codes;
use mbedtls::Result as TlsResult;

use support::rand::test_rng;
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
                match e.high_level() {
                    Some(codes::SslBadProtocolVersion) => {
                        assert!(exp_version.is_none())
                    }
                    Some(codes::SslFatalAlertMessage) => {}
                    _ => panic!("Unexpected error {}", e),
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
    let key = Arc::new(Pk::from_private_key(&mut test_rng(), keys::EXPIRED_KEY.as_bytes(), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    #[cfg(not(feature = "fips"))]
    if min_version == Version::Tls13 || max_version == Version::Tls13 {
        let sig_algs = Arc::new(mbedtls::ssl::tls13_preset_default_sig_algs());
        config.set_signature_algorithms(sig_algs);
    }
    config.push_cert(cert, key)?;
    let mut context = Context::new(Arc::new(config));

    match context.establish_async(conn, None).await {
        Ok(()) => {
            assert_eq!(context.version(), exp_version.unwrap());
        }
        Err(e) => {
            match (e.low_level(), e.high_level()) {
        // client just closes connection instead of sending alert
                (Some(codes::NetSendFailed), _) => {
                    assert!(exp_version.is_none())
                }
                (_, Some(codes::SslBadProtocolVersion)) => {}
                _ => panic!("Unexpected error {}", e),
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
    let key = Arc::new(Pk::from_private_key(&mut test_rng(), keys::EXPIRED_KEY.as_bytes(), None).unwrap());

    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key).unwrap();
    let mut context = Context::new(Arc::new(config));

    context.establish_async(conn, None).await.unwrap();

    f(context).await
}

#[cfg(unix)]
mod test {
    use mbedtls::ssl::Version;
    use rstest::rstest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    async fn run_async_session_client_server_test(config: TestConfig) {
        let min_c = config.min_c;
        let max_c = config.max_c;
        let min_s = config.min_s;
        let max_s = config.max_s;
        let exp_ver = config.exp_ver;

        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
        let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver.clone()));
        let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver));

        c.await.unwrap().unwrap();
        s.await.unwrap().unwrap();
    }

    #[rstest]
    #[case::client1_2_server1_2(TestConfig::new(
        Version::Tls12,
        Version::Tls12,
        Version::Tls12,
        Version::Tls12,
        Some(Version::Tls12)
    ))]
    #[tokio::test]
    async fn async_session_client_server_tls12_test(#[case] config: TestConfig) {
        run_async_session_client_server_test(config).await;
    }

    #[cfg(not(feature = "fips"))]
    #[rstest]
    #[case::client_mix_server1_2(TestConfig::new(
        Version::Tls12,
        Version::Tls13,
        Version::Tls12,
        Version::Tls12,
        Some(Version::Tls12)
    ))]
    #[case::client1_3_server1_3(TestConfig::new(
        Version::Tls13,
        Version::Tls13,
        Version::Tls13,
        Version::Tls13,
        Some(Version::Tls13)
    ))]
    #[case::client_mix_server1_3(TestConfig::new(
        Version::Tls12,
        Version::Tls13,
        Version::Tls13,
        Version::Tls13,
        Some(Version::Tls13)
    ))]
    #[case::client1_2_server_mix(TestConfig::new(
        Version::Tls12,
        Version::Tls12,
        Version::Tls12,
        Version::Tls13,
        Some(Version::Tls12)
    ))]
    #[case::client1_3_server_mix(TestConfig::new(
        Version::Tls13,
        Version::Tls13,
        Version::Tls12,
        Version::Tls13,
        Some(Version::Tls13)
    ))]
    #[case::client_mix_server_mix(TestConfig::new(
        Version::Tls12,
        Version::Tls13,
        Version::Tls12,
        Version::Tls13,
        Some(Version::Tls13)
    ))]
    #[tokio::test]
    async fn async_session_client_server_tls13_test(#[case] config: TestConfig) {
        run_async_session_client_server_test(config).await;
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
    async fn write_large_buffer_ok() {
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize = 3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
        let c = tokio::spawn(super::with_client(c, move |mut session| {
            Box::pin(async move {
                session.write_all(&data_to_write).await.unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, move |mut session| {
            Box::pin(async move {
                let mut buf = vec![0; buffer_size];
                match session.read_exact(&mut buf).await {
                    Ok(n) => {
                        assert_eq!(n, buffer_size, "wrong length");
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

    /// write large buffer should ok when `poll_write` is getting an unchanging
    /// buffer when meet `Poll::Pending`
    #[tokio::test]
    async fn write_large_buffer_ok_with_unchanging_buffer() {
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize = 3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
        let c = tokio::spawn(super::with_client(c, move |mut session| {
            Box::pin(async move {
                // use a custom future for writing all buffer, which always use different length
                // when calling `poll_write`
                crate::support::custom_write_all::custom_write_all(&mut session, &data_to_write, 1)
                    .await
                    .unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, move |mut session| {
            Box::pin(async move {
                let mut buf = vec![0; buffer_size];
                match session.read_exact(&mut buf).await {
                    Ok(n) => {
                        assert_eq!(n, buffer_size, "wrong length");
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

    /// write large buffer should ok when `poll_write` is getting a increasing
    /// buffer when meet `Poll::Pending`
    #[tokio::test]
    async fn write_large_buffer_ok_with_changing_buffer_1() {
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize = 3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
        let c = tokio::spawn(super::with_client(c, move |mut session| {
            Box::pin(async move {
                // use a custom future for writing all buffer, which always use different length
                // when calling `poll_write`
                crate::support::custom_write_all::custom_write_all(&mut session, &data_to_write, 1)
                    .await
                    .unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, move |mut session| {
            Box::pin(async move {
                let mut buf = vec![0; buffer_size];
                match session.read_exact(&mut buf).await {
                    Ok(n) => {
                        assert_eq!(n, buffer_size, "wrong length");
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

    /// write large buffer should ok when `poll_write` is getting a decreasing
    /// buffer when meet `Poll::Pending`
    #[tokio::test]
    async fn write_large_buffer_ok_with_changing_buffer_2() {
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize = 3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
        let c = tokio::spawn(super::with_client(c, move |mut session| {
            Box::pin(async move {
                // use a custom future for writing all buffer, which always use different length
                // when calling `poll_write`
                crate::support::custom_write_all::custom_write_all(&mut session, &data_to_write, 1)
                    .await
                    .unwrap();
                session.shutdown().await.unwrap();
            })
        }));

        let s = tokio::spawn(super::with_server(s, move |mut session| {
            Box::pin(async move {
                let mut buf = vec![0; buffer_size];
                match session.read_exact(&mut buf).await {
                    Ok(n) => {
                        assert_eq!(n, buffer_size, "wrong length");
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
}
