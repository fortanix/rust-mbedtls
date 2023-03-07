/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::stdin;
use std::net::UdpSocket;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;

fn result_main(addr: &str) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes())?);
    let mut config = Config::new(Endpoint::Client, Transport::Datagram, Preset::Default);
    config.set_rng(rng);
    config.set_ca_list(cert, None);
    let mut ctx = Context::new(Arc::new(config));
    ctx.set_timer_callback(Box::new(mbedtls::ssl::context::Timer::new()));

    let sock = UdpSocket::bind("localhost:12345").unwrap();
    let sock = mbedtls::ssl::context::ConnectedUdpSocket::connect(sock, addr).unwrap();
    ctx.establish(sock, None).unwrap();

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    ctx.send(line.as_bytes()).unwrap();
    let mut resp = Vec::with_capacity(100);
    let len = ctx.recv(&mut resp).unwrap();
    if let Ok(s) = std::str::from_utf8(&resp[..len]) {
        println!("{}", s);
    } else {
        eprintln!("Invalid UTF-8 received");
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args();
    args.next();
    result_main(
        &args
            .next()
            .expect("supply destination in command-line argument"),
    )
    .unwrap();
}
