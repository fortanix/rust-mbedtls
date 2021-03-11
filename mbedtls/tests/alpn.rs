/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(dead_code)]
extern crate mbedtls;

use std::net::TcpStream;
use std::thread;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, NullTerminatedStrList, Preset, Transport};
use mbedtls::ssl::{Config, Context, Session};
use mbedtls::x509::{Certificate, LinkedCertificate, VerifyError};
use mbedtls::{Error, Result};

mod support;
use support::entropy::entropy_new;
use support::keys;


#[derive(Debug)]
enum Expected<'a> {
    FailedHandshake(Error),
    SessionEstablished {
        alpn: Option<&'a str>,
    }
}

impl Expected<'_> {
    fn check(self, res: Result<Session<'_>>) {
        match (res, self) {
            (Ok(session), Expected::SessionEstablished { alpn }) => assert_eq!(session.get_alpn_protocol().unwrap(), alpn),
            (Err(e), Expected::FailedHandshake(err)) => assert_eq!(e, err),
            (res, expected) => panic!("Unexpected result, expected {:?}, session is_ok: {}", expected, res.is_ok()),
        }
    }
}

fn client(mut conn: TcpStream, alpn_list: Option<&[&str]>, expected: Expected<'_>) -> Result<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cacert = Certificate::from_pem(keys::ROOT_CA_CERT)?;
    let verify_callback = &mut |_crt: &mut LinkedCertificate, _depth, verify_flags: &mut VerifyError| {
        verify_flags.remove(VerifyError::CERT_EXPIRED);
        Ok(())
    };
    let alpn_list = alpn_list.map(|list| NullTerminatedStrList::new(list));
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_verify_callback(verify_callback);
    config.set_ca_list(Some(&mut *cacert), None);
    if let Some(ref alpn_list) = alpn_list {
        config.set_alpn_protocols(alpn_list)?;
    }
    let mut ctx = Context::new(&config)?;
    let res = ctx.establish(&mut conn, None);
    expected.check(res);
    Ok(())
}

fn server(mut conn: TcpStream, alpn_list: Option<&[&str]>, expected: Expected<'_>) -> Result<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::EXPIRED_CERT)?;
    let mut key = Pk::from_private_key(keys::EXPIRED_KEY, None)?;
    let alpn_list = alpn_list.map(|list| NullTerminatedStrList::new(list));
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.push_cert(&mut *cert, &mut key)?;
    if let Some(ref alpn_list) = alpn_list {
        config.set_alpn_protocols(alpn_list)?;
    }
    let mut ctx = Context::new(&config)?;

    let res = ctx.establish(&mut conn, None);
    expected.check(res);
    Ok(())
}

#[test]
fn alpn() {
    #[derive(Clone)]
    struct TestConfig {
        client_list: Option<&'static [&'static str]>,
        server_list: Option<&'static [&'static str]>,
        expected: Option<&'static str>,
    }

    impl TestConfig {
        fn new(client_list: Option<&'static [&'static str]>, server_list: Option<&'static [&'static str]>, expected: Option<&'static str>) -> Self {
            Self { client_list, server_list, expected }
        }
    }

    let test_configs = vec![
        TestConfig::new(Some(&["h2\0", "http/1.1\0"]), Some(&["h2\0", "http/1.1\0"]), Some("h2")),
        TestConfig::new(Some(&["http/1.1\0", "h2\0"]), Some(&["h2\0", "http/1.1\0"]), Some("h2")),
        TestConfig::new(Some(&["h2\0", "http/1.1\0"]), Some(&["http/1.1\0", "h2\0"]), Some("http/1.1")),
        TestConfig::new(None, None, None),
        TestConfig::new(None, Some(&["h2\0", "http/1.1\0"]), None),
        TestConfig::new(Some(&["h2\0", "http/1.1\0"]), None, None),
    ];

    for config in test_configs {
        let client_list = config.client_list;
        let server_list = config.server_list;
        let alpn = config.expected;
        let (c, s) = support::net::create_tcp_pair().unwrap();
        let c = thread::spawn(move || client(c, client_list, Expected::SessionEstablished { alpn }).unwrap());
        let s = thread::spawn(move || server(s, server_list, Expected::SessionEstablished { alpn }).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}

#[test]
fn nothing_in_common() {
    let (c, s) = support::net::create_tcp_pair().unwrap();
    let c = thread::spawn(move || client(c, Some(&["a1\0", "a2\0"]), Expected::FailedHandshake(Error::SslFatalAlertMessage)).unwrap());
    let s = thread::spawn(move || server(s, Some(&["b1\0", "b2\0"]), Expected::FailedHandshake(Error::SslBadHsClientHello)).unwrap());
    c.join().unwrap();
    s.join().unwrap();
}
