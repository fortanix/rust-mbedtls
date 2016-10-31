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
use std::io::{Read,Write};

use mbedtls::Result as TlsResult;
use mbedtls::rng::CtrDrbg;
use mbedtls::x509::Certificate;
use mbedtls::pk::Pk;
use mbedtls::ssl::config::{Endpoint,Transport,Preset};
use mbedtls::ssl::{Config,Context};

mod support;
use support::keys;
use support::entropy::entropy_new;

fn client(mut conn: TcpStream) -> TlsResult<()> {
	let mut entropy=entropy_new();
	let mut rng=try!(CtrDrbg::new(&mut entropy,None));
	let mut cert=try!(Certificate::from_pem(keys::PEM_CERT));
	let mut config=Config::new(Endpoint::Client,Transport::Stream,Preset::Default);
	config.set_rng(Some(&mut rng));
	config.set_ca_list(Some(&mut *cert),None);
	let mut ctx=try!(Context::new(&config));
	
	let mut session=try!(ctx.establish(&mut conn));

	session.write_all(b"Client2Server").unwrap();
	let mut buf=[0u8;13];
	session.read_exact(&mut buf).unwrap();
	assert_eq!(&buf,b"Server2Client");
	Ok(())
}

fn server(mut conn: TcpStream) -> TlsResult<()> {
	let mut entropy=entropy_new();
	let mut rng=try!(CtrDrbg::new(&mut entropy,None));
	let mut cert=try!(Certificate::from_pem(keys::PEM_CERT));
	let mut key=try!(Pk::from_private_key(keys::PEM_KEY,None));
	let mut config=Config::new(Endpoint::Server,Transport::Stream,Preset::Default);
	config.set_rng(Some(&mut rng));
	try!(config.push_cert(&mut *cert,&mut key));
	let mut ctx=try!(Context::new(&config));
	
	let mut session=try!(ctx.establish(&mut conn));

	session.write_all(b"Server2Client").unwrap();
	let mut buf=[0u8;13];
	session.read_exact(&mut buf).unwrap();
	assert_eq!(&buf,b"Client2Server");
	Ok(())
}

#[cfg(unix)]
mod test {
	extern crate libc;
	use std::net::TcpStream;
	use std::os::unix::io::FromRawFd;
	use std::io::{Result as IoResult,Error as IoError};
	use std::thread;
	
	fn create_tcp_pair() -> IoResult<(TcpStream,TcpStream)> {
		let mut fds: [libc::c_int;2]=[0;2];
		unsafe {
			// one might consider creating a TcpStream from a UNIX socket a hack
			// most socket operations should work the same way, and UnixSocket
			// is too new to be used
			if libc::socketpair(libc::AF_UNIX,libc::SOCK_STREAM,0,fds.as_mut_ptr())==0 {
				Ok((TcpStream::from_raw_fd(fds[0]),TcpStream::from_raw_fd(fds[1])))
			} else {
				Err(IoError::last_os_error())
			}
		}
	}
	
	#[test]
	fn client_server_test() {
		let (c,s)=create_tcp_pair().unwrap();
		
		let c=thread::spawn(move||super::client(c).unwrap());
		let s=thread::spawn(move||super::server(s).unwrap());
		c.join().unwrap();
		s.join().unwrap();
	}
}
