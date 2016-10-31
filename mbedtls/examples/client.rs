/*
 * Rust interface for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

extern crate mbedtls;

use std::net::TcpStream;
use std::io::{stdin,stdout,self,Write};

use mbedtls::Result as TlsResult;
use mbedtls::rng::CtrDrbg;
use mbedtls::x509::Certificate;
use mbedtls::ssl::config::{Endpoint,Transport,Preset};
use mbedtls::ssl::{Config,Context};

#[path="../tests/support/mod.rs"]
mod support;
use support::keys;
use support::entropy::entropy_new;

fn result_main(addr: &str) -> TlsResult<()> {
	let mut entropy=entropy_new();
	let mut rng=try!(CtrDrbg::new(&mut entropy,None));
	let mut cert=try!(Certificate::from_pem(keys::PEM_CERT));
	let mut config=Config::new(Endpoint::Client,Transport::Stream,Preset::Default);
	config.set_rng(Some(&mut rng));
	config.set_ca_list(Some(&mut *cert),None);
	let mut ctx=try!(Context::new(&config));
	
	let mut conn=TcpStream::connect(addr).unwrap();
	let mut session=try!(ctx.establish(&mut conn));

	let mut line=String::new();
	stdin().read_line(&mut line).unwrap();
	session.write_all(line.as_bytes()).unwrap();
	io::copy(&mut session,&mut stdout()).unwrap();
	Ok(())
}

fn main() {
	let mut args=std::env::args();
	args.next();
	result_main(&args.next().expect("supply destination in command-line argument")).unwrap();
}
