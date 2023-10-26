/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;

fn result_main(addr: &str) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client").unwrap();
    let mut ctx = Context::new(Arc::new(config));

    let conn = TcpStream::connect(addr).unwrap();
    ctx.establish(conn, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    ctx.write_all(line.as_bytes()).unwrap();
    io::copy(&mut ctx, &mut stdout()).unwrap();
    Ok(())
}

fn main() {
    let mut args = std::env::args();
    args.next();
    result_main(&args.next().expect("supply destination in command-line argument")).unwrap();
}
