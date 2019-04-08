/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

extern crate mbedtls;

use std::io::{Read, Write};
use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate, LinkedCertificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;

mod support;
use support::entropy::entropy_new;
use support::keys;

fn client(
    mut conn: TcpStream,
    min_minor: i32,
    max_minor: i32,
    exp_minor: Result<i32, ()>,
) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = try!(CtrDrbg::new(&mut entropy, None));
    let mut cert = try!(Certificate::from_pem(keys::PEM_CERT));
    let mut verify_args = None;
    {
        let verify_callback =
            &mut |crt: &mut LinkedCertificate, depth, verify_flags: &mut VerifyError| {
                verify_args = Some((crt.subject().unwrap(), depth, verify_flags.bits()));
                Ok(())
            };
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng));
        config.set_verify_callback(verify_callback);
        config.set_ca_list(Some(&mut *cert), None);
        config.set_min_version(3, min_minor)?;
        config.set_max_version(3, max_minor)?;
        let mut ctx = try!(Context::new(&config));

        let session = ctx.establish(&mut conn, None);

        let mut session = match session {
            Ok(s) => {
                assert_eq!(s.minor_version(), exp_minor.unwrap());
                s
            }
            Err(e) => {
                assert!(exp_minor.is_err());
                match e {
                    Error::SslBadHsProtocolVersion => {}
                    Error::SslFatalAlertMessage => {}
                    e => panic!("Unexpected error {}", e),
                };
                return Ok(());
            }
        };

        let ciphersuite = session.ciphersuite();
        session
            .write_all(format!("Client2Server {:4x}", ciphersuite).as_bytes())
            .unwrap();
        let mut buf = [0u8; 13 + 4 + 1];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
    } // drop verify_callback, releasing borrow of verify_args
    assert_eq!(verify_args, Some((keys::PEM_CERT_SUBJECT.to_owned(), 0, 0)));
    Ok(())
}

fn server(
    mut conn: TcpStream,
    min_minor: i32,
    max_minor: i32,
    exp_minor: Result<i32, ()>,
) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = try!(CtrDrbg::new(&mut entropy, None));
    let mut cert = try!(Certificate::from_pem(keys::PEM_CERT));
    let mut key = try!(Pk::from_private_key(keys::PEM_KEY, None));
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_min_version(3, min_minor)?;
    config.set_max_version(3, max_minor)?;
    try!(config.push_cert(&mut *cert, &mut key));
    let mut ctx = try!(Context::new(&config));

    let session = ctx.establish(&mut conn, None);
    let mut session = match session {
        Ok(s) => {
            assert_eq!(s.minor_version(), exp_minor.unwrap());
            s
        }
        Err(e) => {
            assert!(exp_minor.is_err());
            match e {
                // client just closes connection instead of sending alert
                Error::NetSendFailed => {}
                Error::SslBadHsProtocolVersion => {}
                e => panic!("Unexpected error {}", e),
            };
            return Ok(());
        }
    };

    let ciphersuite = session.ciphersuite();
    session
        .write_all(format!("Server2Client {:4x}", ciphersuite).as_bytes())
        .unwrap();
    let mut buf = [0u8; 13 + 1 + 4];
    session.read_exact(&mut buf).unwrap();

    assert_eq!(&buf, format!("Client2Server {:4x}", ciphersuite).as_bytes());
    Ok(())
}

#[cfg(unix)]
mod test {
    use std::thread;
    use support::net::create_tcp_pair;

    #[test]
    fn client_server_test() {
        let test_configs = [
            [0, 0, 0, 0, 0],
            [1, 1, 1, 1, 1],
            [2, 2, 2, 2, 2],
            [1, 1, 0, 2, 1],
            [0, 2, 0, 1, 1],
            [1, 2, 1, 1, 1],
            [1, 2, 1, 2, 2],
            [2, 2, 1, 2, 2],
            [1, 3, 1, 2, 2],
            [0, 3, 0, 3, 3],
            [1, 3, 2, 3, 3],
            [3, 3, 3, 3, 3],
            [2, 2, 3, 2, -1],
            [2, 2, 0, 1, -1],
            [0, 1, 2, 2, -1],
            [0, 0, 1, 2, -1],
        ];

        for config in &test_configs {
            let client_min_ver = config[0];
            let client_max_ver = config[1];
            let server_min_ver = config[2];
            let server_max_ver = config[3];
            let exp_version = config[4];

            if (client_max_ver < 3 || server_max_ver < 3) && !cfg!(feature = "legacy_protocols") {
                continue;
            }

            let (c, s) = create_tcp_pair().unwrap();

            let c = thread::spawn(move || {
                let exp_result = if exp_version < 0 {
                    Err(())
                } else {
                    Ok(exp_version)
                };
                super::client(c, client_min_ver, client_max_ver, exp_result).unwrap()
            });

            let s = thread::spawn(move || {
                let exp_result = if exp_version < 0 {
                    Err(())
                } else {
                    Ok(exp_version)
                };
                super::server(s, server_min_ver, server_max_ver, exp_result).unwrap()
            });

            c.join().unwrap();
            s.join().unwrap();
        }
    }
}
