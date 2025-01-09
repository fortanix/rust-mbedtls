/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(dead_code)]

#[cfg(all(feature = "std", feature = "async"))]
pub mod custom_write_all;
pub mod entropy;
pub mod keys;
#[cfg(unix)]
#[cfg(sys_std_component = "net")]
pub mod net;
pub mod rand;

#[cfg(feature = "std")]
use std::thread::{Builder, JoinHandle};
#[cfg(feature = "std")]
pub fn thread_spawn_named<F, T, S>(name: S, f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
    S: Into<String>,
{
    Builder::new().name(name.into()).spawn(f).unwrap()
}
