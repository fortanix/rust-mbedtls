/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or 
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version 
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your 
 * option. This file may not be copied, modified, or distributed except 
 * according to those terms. */

extern crate mbedtls;

use std::net::TcpStream;
use std::io::{Read, Write};

use mbedtls::Result as TlsResult;
use mbedtls::rng::CtrDrbg;
use mbedtls::x509::{Certificate, LinkedCertificate, VerifyError};
use mbedtls::pk::Pk;
use mbedtls::ssl::config::{Endpoint, Transport, Preset};
use mbedtls::ssl::{Config, Context};

mod support;
use support::keys;
use support::entropy::entropy_new;

fn client(mut conn: TcpStream) -> TlsResult<()> {
	let mut entropy = entropy_new();
	let mut rng = try!(CtrDrbg::new(&mut entropy, None));
	let mut cert = try!(Certificate::from_pem(keys::PEM_CERT));
	let mut verify_args = None;
	{
		let verify_callback = &mut |crt: &mut LinkedCertificate, depth, verify_flags: &mut VerifyError| {
			verify_args = Some((crt.subject().unwrap(), depth, verify_flags.bits()));
			Ok(())
		};
		let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
		config.set_rng(Some(&mut rng));
		config.set_verify_callback(verify_callback);
		config.set_ca_list(Some(&mut *cert), None);
		let mut ctx = try!(Context::new(&config));

		let mut session = try!(ctx.establish(&mut conn, None));

		session.write_all(b"Client2Server").unwrap();
		let mut buf = [0u8; 13];
		session.read_exact(&mut buf).unwrap();
		assert_eq!(&buf, b"Server2Client");
	} // drop verify_callback, releasing borrow of verify_args
	assert_eq!(verify_args, Some((keys::PEM_CERT_SUBJECT.to_owned(), 0, 0)));
	Ok(())
}

fn server(mut conn: TcpStream) -> TlsResult<()> {
	let mut entropy = entropy_new();
	let mut rng = try!(CtrDrbg::new(&mut entropy, None));
	let mut cert = try!(Certificate::from_pem(keys::PEM_CERT));
	let mut key = try!(Pk::from_private_key(keys::PEM_KEY, None));
	let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
	config.set_rng(Some(&mut rng));
	try!(config.push_cert(&mut *cert, &mut key));
	let mut ctx = try!(Context::new(&config));

	let mut session = try!(ctx.establish(&mut conn, None));

	session.write_all(b"Server2Client").unwrap();
	let mut buf = [0u8; 13];
	session.read_exact(&mut buf).unwrap();
	assert_eq!(&buf, b"Client2Server");
	Ok(())
}

#[cfg(unix)]
mod test {
	use std::thread;
	use support::net::create_tcp_pair;

	#[test]
	fn client_server_test() {
		let (c, s) = create_tcp_pair().unwrap();

		let c = thread::spawn(move || super::client(c).unwrap());
		let s = thread::spawn(move || super::server(s).unwrap());
		c.join().unwrap();
		s.join().unwrap();
	}
}
