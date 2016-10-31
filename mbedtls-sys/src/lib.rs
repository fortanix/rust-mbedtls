/*
 * Rust bindings for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version. Alternatively, you can redistribute it and/or modify it
 * under the terms of the Apache License, Version 2.0. 
 */

#![cfg_attr(not(feature="std"),no_std)]
#[cfg(feature="std")]
extern crate core;

pub mod types;
include!(concat!(env!("OUT_DIR"), "/mod-bindings.rs"));

pub use bindings::*;
