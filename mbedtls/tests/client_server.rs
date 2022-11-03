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
use std::borrow::Cow;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::{ConnectedUdpSocket, IoCallback, Timer};
use mbedtls::ssl::{Config, Context, CookieContext, Version};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;
use std::sync::Arc;

use mbedtls_sys::types::raw_types::*;
use mbedtls_sys::types::size_t;

mod support;
use support::entropy::entropy_new;
use support::keys;
use support::rand::test_rng;

/// Simple type to unify TCP and UDP connections, to support both TLS and DTLS
enum Connection {
    Tcp(TcpStream),
    Udp(ConnectedUdpSocket),
}

impl IoCallback for Connection {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let conn = &mut *(user_data as *mut Connection);
        match conn {
            Connection::Tcp(c) => TcpStream::call_recv(c.data_ptr(), data, len),
            Connection::Udp(c) => ConnectedUdpSocket::call_recv(c.data_ptr(), data, len),
        }
    }

    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
        let conn = &mut *(user_data as *mut Connection);
        match conn {
            Connection::Tcp(c) => TcpStream::call_send(c.data_ptr(), data, len),
            Connection::Udp(c) => ConnectedUdpSocket::call_send(c.data_ptr(), data, len),
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut Connection as *mut c_void
    }
}

fn client(
    conn: Connection,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = match conn {
        Connection::Tcp(_) => Config::new(Endpoint::Client, Transport::Stream, Preset::Default),
        Connection::Udp(_) => Config::new(Endpoint::Client, Transport::Datagram, Preset::Default),
    };
    let c_dbg_callback = |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
        println!("client {} {}:{} {}", level, file, line, message);
    };
    config.set_dbg_callback(c_dbg_callback.clone());

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
    if let Connection::Udp(_) = conn {
        ctx.set_timer_callback(Box::new(Timer::new()));
    }

    match ctx.establish(conn, None) {
        Ok(()) => {
            assert_eq!(ctx.version(), exp_version.unwrap());
        }
        Err(e) => {
            match e {
                Error::SslBadProtocolVersion => {assert!(exp_version.is_none())},
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
    Ok(())
}

fn server(
    conn: Connection,
    min_version: Version,
    max_version: Version,
    exp_version: Option<Version>,
    use_psk: bool,
) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = match conn {
        Connection::Tcp(_) => Config::new(Endpoint::Server, Transport::Stream, Preset::Default),
        Connection::Udp(_) => {
            let mut config = Config::new(Endpoint::Server, Transport::Datagram, Preset::Default);
            // For DTLS, we need a cookie context to work against DoS attacks
            let cookies = CookieContext::new(rng.clone())?;
            config.set_dtls_cookies(Arc::new(cookies));
            config
        }
    };
    let s_dbg_callback = |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
        println!("server {} {}:{} {}", level, file, line, message);
    };
    config.set_dbg_callback(s_dbg_callback.clone());

    config.set_rng(rng);
    config.set_min_version(min_version)?;
    config.set_max_version(max_version)?;

    if min_version == Version::Tls1_3 || max_version == Version::Tls1_3{
        let sig_algs = Arc::new(mbedtls::ssl::tls1_3_preset_default_sig_algs());
        config.set_signature_algorithms(sig_algs);
    }

    if !use_psk { // for certificate-based operation, set up certificates
        let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes())?);
        let key = Arc::new(Pk::from_private_key(&mut test_rng(), keys::EXPIRED_KEY.as_bytes(), None)?);
        config.push_cert(cert, key)?;
    } else { // for psk-based operation, only PSK required
        config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client")?;
    }
    let mut ctx = Context::new(Arc::new(config));

    let res = if let Connection::Udp(_) = conn {
        // For DTLS, timers are required to support retransmissions and the DTLS server needs a client
        // ID to create individual cookies per client
        ctx.set_timer_callback(Box::new(Timer::new()));
        ctx.set_client_transport_id_once(b"127.0.0.1:12341");
        // The first connection setup attempt will fail because the ClientHello is received without
        // a cookie
        match ctx.establish(conn, None) {
            Err(Error::SslHelloVerifyRequired) => {}
            Ok(()) => panic!("SslHelloVerifyRequired expected, got Ok instead"),
            Err(e) => panic!("SslHelloVerifyRequired expected, got {} instead", e),
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
            match e {
                // client just closes connection instead of sending alert
                Error::NetSendFailed => {assert!(exp_version.is_none())},
                Error::SslBadProtocolVersion => {},
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
        use std::net::UdpSocket;
        use mbedtls::ssl::context::ConnectedUdpSocket;

        #[cfg(feature = "debug")]
        mbedtls::set_global_debug_threshold(3);

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
            TestConfig::new(Version::Tls1_2, Version::Tls1_2, Version::Tls1_2, Version::Tls1_2, Some(Version::Tls1_2)),
            TestConfig::new(Version::Tls1_2, Version::Tls1_3, Version::Tls1_3, Version::Tls1_3, Some(Version::Tls1_3)),
            TestConfig::new(Version::Tls1_3, Version::Tls1_3, Version::Tls1_3, Version::Tls1_3, Some(Version::Tls1_3)),
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
            let c = thread::spawn(move || super::client(super::Connection::Tcp(c), min_c, max_c, exp_ver, false).unwrap());
            let s = thread::spawn(move || super::server(super::Connection::Tcp(s), min_s, max_s, exp_ver, false).unwrap());

            c.join().unwrap();
            s.join().unwrap();

            // skip following tests because:
            // 1. DTLS 1.3 is not yet supported, ref: https://github.com/Mbed-TLS/mbedtls/blob/v3.2.1/library/ssl_tls.c#L942
            // 2. embedTLS currently only support the ephemeral or (EC)DHE key echange mode, ref: https://github.com/Mbed-TLS/mbedtls/blob/v3.2.1/library/ssl_tls13_server.c#L820-L822
            //    PKS ext is also not supported now: ref: https://github.com/Mbed-TLS/mbedtls/blob/v3.2.1/docs/architecture/tls13-support.md
            if min_s == Version::Tls1_3 || min_c == Version::Tls1_3{
                continue;
            }

            // TLS tests using PSK

            let (c, s) = crate::support::net::create_tcp_pair().unwrap();
            let c = thread::spawn(move || super::client(super::Connection::Tcp(c), min_c, max_c, exp_ver, true).unwrap());
            let s = thread::spawn(move || super::server(super::Connection::Tcp(s), min_s, max_s, exp_ver, true).unwrap());

            c.join().unwrap();
            s.join().unwrap();

            // DTLS tests using certificates

            let s = UdpSocket::bind("127.0.0.1:12340").expect("could not bind UdpSocket");
            let s = ConnectedUdpSocket::connect(s, "127.0.0.1:12341").expect("could not connect UdpSocket");
            let s = thread::spawn(move || super::server(super::Connection::Udp(s), min_s, max_s, exp_ver, false).unwrap());
            let c = UdpSocket::bind("127.0.0.1:12341").expect("could not bind UdpSocket");
            let c = ConnectedUdpSocket::connect(c, "127.0.0.1:12340").expect("could not connect UdpSocket");
            let c = thread::spawn(move || super::client(super::Connection::Udp(c), min_c, max_c, exp_ver, false).unwrap());

            s.join().unwrap();
            c.join().unwrap();

            // TODO There seems to be a race condition which does not allow us to directly reuse
            // the UDP address? Without a short delay here, the DTLS tests using PSK fail with
            // NetRecvFailed in some cases.
            std::thread::sleep(std::time::Duration::from_millis(10));

            // DTLS tests using PSK

            let s = UdpSocket::bind("127.0.0.1:12340").expect("could not bind UdpSocket");
            let s = ConnectedUdpSocket::connect(s, "127.0.0.1:12341").expect("could not connect UdpSocket");
            let s = thread::spawn(move || super::server(super::Connection::Udp(s), min_s, max_s, exp_ver, true).unwrap());
            let c = UdpSocket::bind("127.0.0.1:12341").expect("could not bind UdpSocket");
            let c = ConnectedUdpSocket::connect(c, "127.0.0.1:12340").expect("could not connect UdpSocket");
            let c = thread::spawn(move || super::client(super::Connection::Udp(c), min_c, max_c, exp_ver, true).unwrap());

            s.join().unwrap();
            c.join().unwrap();
        }
    }
}
