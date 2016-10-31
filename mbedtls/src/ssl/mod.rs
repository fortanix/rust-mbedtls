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
//! This module contains everything related to TLS support.
//!
//! Basic way to setup a TLS session:
//!
//! ```rust,no_run
//! use std::net::TcpStream;
//! use mbedtls::ssl::{Config,Context};
//! use mbedtls::ssl::config::{Endpoint,Preset,Transport};
//!
//! fn establish_tls(conn: &mut TcpStream) -> mbedtls::Result<()> {
//! 	let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
//! 	// TODO: setup configuration
//! 	let mut ctx=try!(Context::new(&config));
//! 	let mut session=try!(ctx.establish(conn));
//!		unimplemented!()
//! }
//! ```
//!
//! A `Config` can be shared between many `Context`s. A `Context` may be
//! re-used after a `Session` terminates.

pub mod ciphersuites;
pub mod config;
pub mod context;

#[doc(inline)]
pub use self::config::Config;
#[doc(inline)]
pub use self::context::{Context,Session};

