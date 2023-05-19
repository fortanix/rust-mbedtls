/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;
use support::rand::test_rng;

fn listen<E, F: FnMut(TcpStream) -> Result<(), E>>(mut handle_client: F) -> Result<(), E> {
    let sock = TcpListener::bind("127.0.0.1:8080").unwrap();
    for conn in sock.incoming().map(Result::unwrap) {
        println!("Connection from {}", conn.peer_addr().unwrap());
        handle_client(conn)?;
    }

    Ok(())
}

fn result_main() -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::PEM_CERT.as_bytes())?);
    let key = Arc::new(Pk::from_private_key(&mut test_rng(),keys::PEM_KEY.as_bytes(), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key)?;

    let rc_config = Arc::new(config);

    listen(move |conn| {
        let mut ctx = Context::new(rc_config.clone());
        ctx.establish(conn, None)?;
        let mut session = BufReader::new(ctx);
        let mut line = Vec::new();
        session.read_until(b'\n', &mut line).unwrap();
        session.get_mut().write_all(&line).unwrap();
        Ok(())
    })
}

fn main() {
    result_main().unwrap();
}
