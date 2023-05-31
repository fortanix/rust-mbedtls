/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::{Read, Write};
use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::Timer;
use mbedtls::ssl::io::{ConnectedUdpSocket, IoCallback};
use mbedtls::ssl::{Config, Context, CookieContext, Io, Version};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::{Error, codes};
use mbedtls::Result as TlsResult;
use std::sync::Arc;

mod support;
use support::entropy::entropy_new;
use support::keys;

trait TransportType: Sized {
    fn get_transport_type() -> Transport;

    fn recv(ctx: &mut Context<Self>, buf: &mut [u8]) -> TlsResult<usize>;
    fn send(ctx: &mut Context<Self>, buf: &[u8]) -> TlsResult<usize>;
}

impl TransportType for TcpStream {
    fn get_transport_type() -> Transport {
        Transport::Stream
    }

    fn recv(ctx: &mut Context<Self>, buf: &mut [u8]) -> TlsResult<usize> {
        ctx.read(buf).map_err(|_| Error::from(codes::NetRecvFailed))
    }

    fn send(ctx: &mut Context<Self>, buf: &[u8]) -> TlsResult<usize> {
        ctx.write(buf).map_err(|_| Error::from(codes::NetSendFailed))
    }
}

impl TransportType for ConnectedUdpSocket {
    fn get_transport_type() -> Transport {
        Transport::Datagram
    }

    fn recv(ctx: &mut Context<Self>, buf: &mut [u8]) -> TlsResult<usize> {
        Io::recv(ctx, buf)
    }

    fn send(ctx: &mut Context<Self>, buf: &[u8]) -> TlsResult<usize> {
        Io::send(ctx, buf)
    }
}

fn client<C: IoCallback<T> + TransportType, T>(
    conn: C,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = Config::new(Endpoint::Client, C::get_transport_type(), Preset::Default);
    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;
    if !use_psk { // for certificate-based operation, set up ca and verification callback
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
            //so removing this flag here prevents the connections from failing with VerifyError
            Ok(())
        };
        config.set_verify_callback(verify_callback);
        config.set_ca_list(cacert, None);
    } else { // for psk-based operation, only PSK required
        config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client")?;
    }
    let mut ctx = Context::new(Arc::new(config));

    // For DTLS, timers are required to support retransmissions
    if C::get_transport_type() == Transport::Datagram {
        ctx.set_timer_callback(Box::new(Timer::new()));
    }

    match ctx.establish(conn, None) {
        Ok(()) => {
            assert_eq!(ctx.version(), exp_version.unwrap());
        }
        Err(e) => {
            match e.high_level() {
                Some(codes::SslBadHsProtocolVersion) => {assert!(exp_version.is_none())},
                Some(codes::SslFatalAlertMessage) => {},
                _ => panic!("Unexpected error {}", e),
            };
            return Ok(());
        }
    };

    let ciphersuite = ctx.ciphersuite().unwrap();
    let buf = format!("Client2Server {:4x}", ciphersuite);
    assert_eq!(<C as TransportType>::send(&mut ctx, buf.as_bytes()).unwrap(), buf.len());
    let mut buf = [0u8; 13 + 4 + 1];
    assert_eq!(<C as TransportType>::recv(&mut ctx, &mut buf).unwrap(), buf.len());
    assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    Ok(())
}

fn server<C: IoCallback<T> + TransportType, T>(
    conn: C,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool,
) -> TlsResult<()> {
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
        match ctx.establish(conn, None) {
            Err(e) => match e.high_level() {
                Some(codes::SslHelloVerifyRequired) => {}
                _ => panic!("SslHelloVerifyRequired expected, got {} instead", e),               
            }
            Ok(()) => panic!("SslHelloVerifyRequired expected, got Ok instead"),
        }
        ctx.handshake()
    } else {
        ctx.establish(conn, None) // For TLS, establish the connection which should just work
    };

    match res {
        Ok(()) => {
            assert_eq!(ctx.version(), exp_version.unwrap());
        }
        Err(e) => {
            match (e.high_level(), e.low_level()) {
                // client just closes connection instead of sending alert
                (_, Some(codes::NetSendFailed)) => {assert!(exp_version.is_none())},
                (Some(codes::SslBadHsProtocolVersion), _) => {},
                _ => panic!("Unexpected error {}", e),
            };
            return Ok(());
        }
    };

    let ciphersuite = ctx.ciphersuite().unwrap();
    let buf = format!("Server2Client {:4x}", ciphersuite);
    assert_eq!(<C as TransportType>::send(&mut ctx, buf.as_bytes()).unwrap(), buf.len());
    let mut buf = [0u8; 13 + 1 + 4];
    assert_eq!(<C as TransportType>::recv(&mut ctx, &mut buf).unwrap(), buf.len());

    assert_eq!(&buf, format!("Client2Server {:4x}", ciphersuite).as_bytes());
    Ok(())
}

fn with_client<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> R,
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

    context.establish(conn, None).unwrap();

    f(context)
}

fn with_server<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> R,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes()).unwrap());
    let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY.as_bytes(), None).unwrap());

    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key).unwrap();
    let mut context = Context::new(Arc::new(config));

    context.establish(conn, None).unwrap();

    f(context)
}

#[cfg(unix)]
mod test {
    use std::thread;

    #[test]
    fn client_server_test() {
        use mbedtls::ssl::Version;
        use std::net::UdpSocket;
        use mbedtls::ssl::io::ConnectedUdpSocket;

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

            // TLS tests using certificates

            let (c, s) = crate::support::net::create_tcp_pair().unwrap();
            let c = thread::spawn(move || super::client(c, min_c, max_c, exp_ver, false).unwrap());
            let s = thread::spawn(move || super::server(s, min_s, max_s, exp_ver, false).unwrap());

            c.join().unwrap();
            s.join().unwrap();

            // TLS tests using PSK

            let (c, s) = crate::support::net::create_tcp_pair().unwrap();
            let c = thread::spawn(move || super::client(c, min_c, max_c, exp_ver, true).unwrap());
            let s = thread::spawn(move || super::server(s, min_s, max_s, exp_ver, true).unwrap());

            c.join().unwrap();
            s.join().unwrap();

            // DTLS tests using certificates

            // DTLS 1.0 is based on TSL 1.1
            if min_c < Version::Tls1_1 || min_s < Version::Tls1_1 || exp_ver.is_none() {
                continue;
            }

            let s = UdpSocket::bind("127.0.0.1:12340").expect("could not bind UdpSocket");
            let s = ConnectedUdpSocket::connect(s, "127.0.0.1:12341").expect("could not connect UdpSocket");
            let s = thread::spawn(move || super::server(s, min_s, max_s, exp_ver, false).unwrap());
            let c = UdpSocket::bind("127.0.0.1:12341").expect("could not bind UdpSocket");
            let c = ConnectedUdpSocket::connect(c, "127.0.0.1:12340").expect("could not connect UdpSocket");
            let c = thread::spawn(move || super::client(c, min_c, max_c, exp_ver, false).unwrap());

            s.join().unwrap();
            c.join().unwrap();

            // TODO There seems to be a race condition which does not allow us to directly reuse
            // the UDP address? Without a short delay here, the DTLS tests using PSK fail with
            // NetRecvFailed in some cases.
            std::thread::sleep(std::time::Duration::from_millis(10));

            // DTLS tests using PSK

            let s = UdpSocket::bind("127.0.0.1:12340").expect("could not bind UdpSocket");
            let s = ConnectedUdpSocket::connect(s, "127.0.0.1:12341").expect("could not connect UdpSocket");
            let s = thread::spawn(move || super::server(s, min_s, max_s, exp_ver, true).unwrap());
            let c = UdpSocket::bind("127.0.0.1:12341").expect("could not bind UdpSocket");
            let c = ConnectedUdpSocket::connect(c, "127.0.0.1:12340").expect("could not connect UdpSocket");
            let c = thread::spawn(move || super::client(c, min_c, max_c, exp_ver, true).unwrap());

            s.join().unwrap();
            c.join().unwrap();
        }
    }
    
    #[cfg(not(feature = "zlib"))]
    #[test]
    fn write_large_buffer_should_ok() {
        use std::io::{Read, Write};
        
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize =  3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair().unwrap();
        let c = thread::spawn(move || super::with_client(c, move |mut session| {
            let ret = session.write_all(&data_to_write);
            assert!(ret.is_ok());
        }));

        let s = thread::spawn(move || super::with_server(s, move |mut session| {
            let mut buf = vec![0; buffer_size];
            match session.read_exact(&mut buf) {
                Ok(()) => {
                    assert!(&buf[..] == &expected_data[..], "wrong read data");
                }
                Err(e) => {
                    panic!("Unexpected error {:?}", e);
                }
            }
        }));

        c.join().unwrap();
        s.join().unwrap();
    }

    /// when turn on `zlib` feature, c-mbedtls could not record buffer with
    /// size > MBEDTLS_SSL_OUT_CONTENT_LEN (default: 16 * 1024)
    /// Ref: mbedtls-sys/vendor/library/ssl_msg.c#L646-L653
    #[cfg(feature = "zlib")]
    #[test]
    fn write_large_buffer_should_fail_with_zlib() {
        use std::io::{Read, Write};
        // create a big truck of data to write&read, so that OS's Tcp buffer will be
        // full filled so that block appears during `mbedtls_ssl_write`
        let buffer_size: usize =  3 * 1024 * 1024;
        let expected_data: Vec<u8> = std::iter::repeat_with(rand::random).take(buffer_size).collect();
        let data_to_write = expected_data.clone();
        assert_eq!(expected_data, data_to_write);
        let (c, s) = crate::support::net::create_tcp_pair().unwrap();
        let c = thread::spawn(move || super::with_client(c, move |mut session| {
            let ret = session.write_all(&data_to_write);
            assert!(ret.is_err());
            let ref err = ret.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Other);
            assert!(err.to_string().contains("SslBadInputData"));
        }));

        let s = thread::spawn(move || super::with_server(s, move |mut session| {
            let mut buf = vec![0; buffer_size];
            match session.read_exact(&mut buf) {
                Ok(()) => {
                    panic!("should return error");
                }
                Err(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
                }
            }
        }));

        c.join().unwrap();
        s.join().unwrap();
    }
}
