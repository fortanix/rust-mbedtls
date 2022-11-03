/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(dead_code)]

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;

mod support;
use support::entropy::entropy_new;
use support::keys;
use std::sync::Arc;
use support::rand::test_rng;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Test {
    CallbackSetVerifyFlags,
    CallbackError,
}

fn client(conn: TcpStream, test: Test) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::PEM_CERT.as_bytes())?);

    let verify_test = test.clone();
    let verify_callback = move |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
        match verify_test {
            Test::CallbackSetVerifyFlags => {
                *verify_flags |= VerifyError::CERT_OTHER;
                Ok(())
            }
            Test::CallbackError => Err(Error::Asn1InvalidData),
        }
    };
    
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_verify_callback(verify_callback);
    config.set_ca_list(cert, None);
    let mut ctx = Context::new(Arc::new(config));

    match (
        test,
        ctx.establish(conn, None)
            .err()
            .expect("should have failed"),
    ) {
        (Test::CallbackSetVerifyFlags, Error::X509CertVerifyFailed) => {
            assert_eq!(
                ctx.verify_result().unwrap_err(),
                VerifyError::CERT_OTHER | VerifyError::CERT_NOT_TRUSTED,
            );
        }
        (Test::CallbackError, Error::Asn1InvalidData) => {}
        (_, err) => assert!(false, "Unexpected error from ctx.establish(): {:?}", err),
    }

    Ok(())
}

fn server(conn: TcpStream) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::PEM_CERT.as_bytes())?);
    let key = Arc::new(Pk::from_private_key(&mut test_rng(), keys::PEM_KEY.as_bytes(), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key)?;
    let mut ctx = Context::new(Arc::new(config));

    let _ = ctx.establish(conn, None);
    Ok(())
}

#[cfg(unix)]
mod test {
    use std::thread;
    use crate::support::net::create_tcp_pair;

    #[test]
    fn callback_set_verify_flags() {
        let (c, s) = create_tcp_pair().unwrap();

        let c =
            thread::spawn(move || super::client(c, super::Test::CallbackSetVerifyFlags).unwrap());
        let s = thread::spawn(move || super::server(s).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_error() {
        let (c, s) = create_tcp_pair().unwrap();

        let c = thread::spawn(move || super::client(c, super::Test::CallbackError).unwrap());
        let s = thread::spawn(move || super::server(s).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}
