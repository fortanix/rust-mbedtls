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

use error::IntoResult;
use ::mbedtls_sys::*;

define!(struct Mpi(mpi) {
	fn init=mpi_init;
	fn drop=mpi_free;
	impl<'a> Into<*>;
});

impl Mpi {
	pub fn new(value: mpi_sint) -> ::Result<Mpi> {
		let mut ret=Self::init();
		try!(unsafe{mpi_lset(&mut ret.inner,value).into_result()});
		Ok(ret)
	}
	
	/// Initialize an MPI number from big endian binary data
	pub fn from_binary(num: &[u8]) -> ::Result<Mpi> {
		let mut ret=Self::init();
		try!(unsafe{mpi_read_binary(&mut ret.inner,num.as_ptr(),num.len()).into_result()});
		Ok(ret)
	}
}

/*
TODO
lots...
*/
