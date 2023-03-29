/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]
extern crate mbedtls;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::async_io::ConnectedAsyncUdpSocket;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::Timer;
use mbedtls::ssl::io::IoCallback;
use mbedtls::ssl::{Config, Context, Version, CookieContext};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};

mod support;
use support::entropy::entropy_new;
use support::keys;
use tokio::net::TcpStream;

trait TransportType: Sized {
    fn get_transport_type() -> Transport;

}

impl TransportType for TcpStream {
    fn get_transport_type() -> Transport {
        Transport::Stream
    }
}

impl TransportType for ConnectedAsyncUdpSocket {
    fn get_transport_type() -> Transport {
        Transport::Datagram
    }
}

use std::task::Context as TaskContext;
async fn client<C, T>(
    conn: C,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool,
) -> TlsResult<()>
where
    C: TransportType + Unpin + 'static + AsyncRead + AsyncWrite,
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut C): IoCallback<T>,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = Config::new(Endpoint::Client, C::get_transport_type(), Preset::Default);
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    if !use_psk {
        // for certificate-based operation, set up ca and verification callback
        let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes())?);
        let expected_flags = VerifyError::empty();
        #[cfg(feature = "time")]
        let expected_flags = expected_flags | VerifyError::CERT_EXPIRED;
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
        config.set_verify_callback(verify_callback);
        config.set_ca_list(cacert, None);
    } else {
        // for psk-based operation, only PSK required
        config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client")?;
    }
    let mut ctx = Context::new(Arc::new(config));
    // For DTLS, timers are required to support retransmissions
    if C::get_transport_type() == Transport::Datagram {
        ctx.set_timer_callback(Box::new(Timer::new()));
    }

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
    let buf = format!("Client2Server {:4x}", ciphersuite);
    assert_eq!(ctx.write(buf.as_bytes()).await.unwrap(), buf.len());
    let mut buf = [0u8; 13 + 4 + 1];
    assert_eq!(ctx.read(&mut buf).await.unwrap(), buf.len());
    assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    Ok(())
}

async fn server<C, T>(
    conn: C,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool,
) -> TlsResult<()> 
where
    C: TransportType + Unpin + 'static + AsyncRead + AsyncWrite,
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut C): IoCallback<T>,
{
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Server, C::get_transport_type(), Preset::Default);
    if C::get_transport_type() == Transport::Datagram {
        // For DTLS, we need a cookie context to work against DoS attacks
        let cookies = CookieContext::new(rng.clone())?;
        config.set_dtls_cookies(Arc::new(cookies));
    }
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    if !use_psk { // for certificate-based operation, set up certificates
        let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes())?);
        let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY.as_bytes(), None)?);
        config.push_cert(cert, key)?;
    } else { // for psk-based operation, only PSK required
        config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client")?;
    }
    let mut ctx = Context::new(Arc::new(config));

    let res = if C::get_transport_type() == Transport::Datagram {
        // For DTLS, timers are required to support retransmissions and the DTLS server needs a client
        // ID to create individual cookies per client
        ctx.set_timer_callback(Box::new(Timer::new()));
        ctx.set_client_transport_id_once(b"127.0.0.1:12341");
        // The first connection setup attempt will fail because the ClientHello is received without
        // a cookie
        match ctx.establish_async(conn, None).await {
            Err(Error::SslHelloVerifyRequired) => {}
            Ok(()) => panic!("SslHelloVerifyRequired expected, got Ok instead"),
            Err(e) => panic!("SslHelloVerifyRequired expected, got {} instead", e),
        }
        ctx.handshake_async().await
    } else {
        ctx.establish_async(conn, None).await // For TLS, establish the connection which should just work
    };

    match res {
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
    let buf = format!("Server2Client {:4x}", ciphersuite);
    assert_eq!(ctx.write(buf.as_bytes()).await.unwrap(), buf.len());
    let mut buf = [0u8; 13 + 1 + 4];
    assert_eq!(ctx.read(&mut buf).await.unwrap(), buf.len());

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
    use mbedtls::ssl::async_io::ConnectedAsyncUdpSocket;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket};

    #[tokio::test]
    async fn asyncsession_client_server_test() {
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

            // TLS tests using certificates

            let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
            let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver, false));
            let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver, false));

            c.await.unwrap().unwrap();
            s.await.unwrap().unwrap();
            
            // TLS tests using PSK

            let (c, s) = crate::support::net::create_tcp_pair_async().unwrap();
            let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver, true));
            let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver, true));

            c.await.unwrap().unwrap();
            s.await.unwrap().unwrap();

            // DTLS tests using certificates

            // DTLS 1.0 is based on TSL 1.1
            if min_c < Version::Tls1_1 || min_s < Version::Tls1_1 || exp_ver.is_none() {
                continue;
            }

            let s = UdpSocket::bind("127.0.0.1:12340").await.expect("could not bind UdpSocket");
            let s = ConnectedAsyncUdpSocket::connect(s, "127.0.0.1:12341").await.expect("could not connect UdpSocket");
            let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver, false));
            let c = UdpSocket::bind("127.0.0.1:12341").await.expect("could not bind UdpSocket");
            let c = ConnectedAsyncUdpSocket::connect(c, "127.0.0.1:12340").await.expect("could not connect UdpSocket");
            let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver, false));
            

            s.await.unwrap().unwrap();
            c.await.unwrap().unwrap();

            // TODO There seems to be a race condition which does not allow us to directly reuse
            // the UDP address? Without a short delay here, the DTLS tests using PSK fail with
            // NetRecvFailed in some cases.
            std::thread::sleep(std::time::Duration::from_millis(10));

            // DTLS tests using PSK

            let s = UdpSocket::bind("127.0.0.1:12340").await.expect("could not bind UdpSocket");
            let s = ConnectedAsyncUdpSocket::connect(s, "127.0.0.1:12341").await.expect("could not connect UdpSocket");
            let s = tokio::spawn(super::server(s, min_s, max_s, exp_ver, true));
            let c = UdpSocket::bind("127.0.0.1:12341").await.expect("could not bind UdpSocket");
            let c = ConnectedAsyncUdpSocket::connect(c, "127.0.0.1:12340").await.expect("could not connect UdpSocket");
            let c = tokio::spawn(super::client(c, min_c, max_c, exp_ver, true));

            s.await.unwrap().unwrap();
            c.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn asyncsession_shutdown1() {
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
    async fn asyncsession_shutdown2() {
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
    async fn asyncsession_shutdown3() {
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
}
