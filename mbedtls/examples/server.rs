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

use std::net::{TcpListener,TcpStream};
use std::io::{BufReader,BufRead,Write};

use mbedtls::Result as TlsResult;
use mbedtls::rng::CtrDrbg;
use mbedtls::x509::Certificate;
use mbedtls::pk::Pk;
use mbedtls::ssl::config::{Endpoint,Transport,Preset};
use mbedtls::ssl::{Config,Context};

#[path="../tests/support/mod.rs"]
mod support;
use support::keys;
use support::entropy::entropy_new;

fn listen<E,F: FnMut(TcpStream) -> Result<(),E>>(mut handle_client: F) -> Result<(),E> {
	let sock=TcpListener::bind("127.0.0.1:8080").unwrap();
	for conn in sock.incoming().map(Result::unwrap) {
		println!("Connection from {}",conn.peer_addr().unwrap());
		try!(handle_client(conn));
	}
	Ok(())
}

fn result_main() -> TlsResult<()> {
	let mut entropy=entropy_new();
	let mut rng=try!(CtrDrbg::new(&mut entropy,None));
	let mut cert=try!(Certificate::from_pem(keys::PEM_CERT));
	let mut key=try!(Pk::from_private_key(keys::PEM_KEY,None));
	let mut config=Config::new(Endpoint::Server,Transport::Stream,Preset::Default);
	config.set_rng(Some(&mut rng));
	try!(config.push_cert(&mut *cert,&mut key));
	let mut ctx=try!(Context::new(&config));
	
	listen(|mut conn|{
		let mut session=BufReader::new(try!(ctx.establish(&mut conn)));
		let mut line=Vec::new();
		session.read_until(b'\n',&mut line).unwrap();
		session.get_mut().write_all(&line).unwrap();
		Ok(())
	})
}

fn main() {
	result_main().unwrap();
}
