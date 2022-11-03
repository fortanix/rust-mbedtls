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
use std::sync::Arc;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate};
use mbedtls::Result as TlsResult;
use mbedtls::ssl::config::CaCallback;

mod support;
use support::entropy::entropy_new;
use support::rand::test_rng;

use mbedtls::alloc::{List as MbedtlsList};

fn client<F>(conn: TcpStream, ca_callback: F) -> TlsResult<()>
    where
        F: CaCallback + Send + 'static,
{
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_ca_callback(ca_callback);
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None).map(|_| ())
}

fn server(conn: TcpStream, cert: &[u8], key: &[u8]) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(cert)?);
    let key = Arc::new(Pk::from_private_key(&mut test_rng(), key, None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key)?;
    let mut ctx = Context::new(Arc::new(config));

    let _ = ctx.establish(conn, None);
    Ok(())
}

#[cfg(unix)]
mod test {
    use super::*;
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::support::keys;
    use mbedtls::x509::{Certificate};
    use mbedtls::Error;

    // This callback should accept any valid self-signed certificate
    fn self_signed_ca_callback(child: &MbedtlsList<Certificate>) -> TlsResult<MbedtlsList<Certificate>> {
        Ok(child.clone())
    }

    #[test]
    fn callback_standard_ca() {
        let (c, s) = create_tcp_pair().unwrap();

        let ca_callback =
            |_: &MbedtlsList<Certificate>| -> TlsResult<MbedtlsList<Certificate>> {
                Ok(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes()).unwrap())
            };
        let c = thread::spawn(move || super::client(c, ca_callback).unwrap());
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT.as_bytes(), keys::PEM_KEY.as_bytes()).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_no_ca() {
        let (c, s) = create_tcp_pair().unwrap();
        let ca_callback =
            |_: &MbedtlsList<Certificate>| -> TlsResult<MbedtlsList<Certificate>> {
                Ok(MbedtlsList::<Certificate>::new())
            };
        let c = thread::spawn(move || {
            let result = super::client(c, ca_callback);
            assert_eq!(result, Err(Error::X509CertVerifyFailed));
        });
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT.as_bytes(), keys::PEM_KEY.as_bytes()).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed() {
        let (c, s) = create_tcp_pair().unwrap();
        let c = thread::spawn(move || super::client(c, self_signed_ca_callback).unwrap());
        let s = thread::spawn(move || super::server(s, keys::PEM_SELF_SIGNED_CERT, keys::PEM_SELF_SIGNED_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed_leaf_cert() {
        // We set up the server to supply a non-self-signed leaf certificate. It should be rejected
        // by the client, because the ca_callback should only accept self-signed certificates.
        let (c, s) = create_tcp_pair().unwrap();
        let c = thread::spawn(move || {
            let result = super::client(c, self_signed_ca_callback);
            assert_eq!(result, Err(Error::X509CertVerifyFailed));
        });
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT.as_bytes(), keys::PEM_KEY.as_bytes()).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed_invalid_sig() {
        // We set up the server to supply a self-signed certificate with an invalid signature. It
        // should be rejected by the client.
        let (c, s) = create_tcp_pair().unwrap();
        let c = thread::spawn(move || {
            let result = super::client(c, self_signed_ca_callback);
            assert_eq!(result, Err(Error::X509CertVerifyFailed));
        });
        let s = thread::spawn(move || super::server(s, keys::PEM_SELF_SIGNED_CERT_INVALID_SIG, keys::PEM_SELF_SIGNED_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}
