/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use error::IntoResult;
use mbedtls_sys::*;

define!(struct Mpi(mpi) {
	fn init=mpi_init;
	fn drop=mpi_free;
	impl<'a> Into<*>;
});

impl Mpi {
    pub fn new(value: mpi_sint) -> ::Result<Mpi> {
        let mut ret = Self::init();
        try!(unsafe { mpi_lset(&mut ret.inner, value).into_result() });
        Ok(ret)
    }

    /// Initialize an MPI number from big endian binary data
    pub fn from_binary(num: &[u8]) -> ::Result<Mpi> {
        let mut ret = Self::init();
        try!(unsafe { mpi_read_binary(&mut ret.inner, num.as_ptr(), num.len()).into_result() });
        Ok(ret)
    }
}

// TODO
// lots...
//
