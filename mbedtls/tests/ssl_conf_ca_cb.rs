/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(dead_code)]
#![cfg(feature = "trusted_cert_cb")]
extern crate mbedtls;

use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate, LinkedCertificate};
use mbedtls::Error;
use mbedtls::Result as TlsResult;

mod support;
use support::entropy::entropy_new;
use support::keys;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Test {
    CallbackValidCa,
    CallbackNoCas,
}

fn client(mut conn: TcpStream, test: Test) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let certs = match test {
        Test::CallbackValidCa => vec![Certificate::from_pem(keys::PEM_CERT)?],
        Test::CallbackNoCas => vec![],
    };
    let ca_callback =
        &mut |_child: &LinkedCertificate| -> TlsResult<Vec<Certificate>> {
            Ok(certs.clone())
        };
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_ca_callback(ca_callback);
    let mut ctx = Context::new(&config)?;

    match (test, ctx.establish(&mut conn, None)) {
        (Test::CallbackValidCa, Ok(_)) => {}
        (Test::CallbackNoCas, Err(Error::X509CertVerifyFailed)) => {}
        (_, Ok(_)) => assert!(false, "ctx.establish() succeeded when it should have failed"),
        (_, Err(err)) => assert!(false, "Unexpected result from ctx.establish(): {:?}", err),
    }
    Ok(())
}

fn server(mut conn: TcpStream) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::PEM_CERT)?;
    let mut key = Pk::from_private_key(keys::PEM_KEY, None)?;
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.push_cert(&mut *cert, &mut key)?;
    let mut ctx = Context::new(&config)?;

    let _ = ctx.establish(&mut conn, None);
    Ok(())
}

#[cfg(unix)]
mod test {
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::Test;

    #[test]
    fn callback_valid_ca() {
        let (c, s) = create_tcp_pair().unwrap();

        let c =
            thread::spawn(move || super::client(c, Test::CallbackValidCa).unwrap());
        let s = thread::spawn(move || super::server(s).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_no_cas() {
        let (c, s) = create_tcp_pair().unwrap();

        let c =
            thread::spawn(move || super::client(c, Test::CallbackNoCas).unwrap());
        let s = thread::spawn(move || super::server(s).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

}
