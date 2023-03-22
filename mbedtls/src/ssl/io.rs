/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */
//! Various I/O abstractions for use with MbedTLS's TLS sessions.
//!
//! If you are using `std::net::TcpStream` or any `std::io::Read` and
//! `std::io::Write` streams, you probably don't need to look at any of this.
//! Just pass your stream directly to `Context::establish`. If you want to use
//! a `std::net::UdpSocket` with DTLS, take a look at `ConnectedUdpSocket`. If
//! you are implementing your own communication types or traits, consider
//! implementing `Io` for them. If all else fails, implement `IoCallback`.

#[cfg(feature = "std")]
use std::{
    io::{Read, Write, Result as IoResult, Error as IoError, ErrorKind as IoErrorKind},
    net::UdpSocket,
    result::Result as StdResult,
};

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

#[cfg(feature = "std")]
use crate::error::Error;
use crate::error::Result;
use super::context::Context;

/// A direct representation of the `mbedtls_ssl_send_t` and `mbedtls_ssl_recv_t`
/// callback function pointers.
///
/// You probably want to implement `IoCallback` instead.
pub trait IoCallbackUnsafe<T> {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int where Self: Sized;
    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int where Self: Sized;
    fn data_ptr(&mut self) -> *mut c_void;
}

/// A safe representation of the `mbedtls_ssl_send_t` and `mbedtls_ssl_recv_t`
/// callback function pointers.
///
/// `T` specifies whether this abstracts an implementation of `std::io::Read`
/// and `std::io::Write` or the more generic `Io` type. See the `Stream` and
/// `AnyIo` types in this module.
pub trait IoCallback<T> {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn send(&mut self, buf: &[u8]) -> Result<usize>;
}

impl<IO: IoCallback<T>, T> IoCallbackUnsafe<T> for IO {
    unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).recv(::core::slice::from_raw_parts_mut(data, len)) {
            Ok(i) => i as c_int,
            Err(e) => e.to_int(),
        }
    }

    unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).send(::core::slice::from_raw_parts(data, len)) {
            Ok(i) => i as c_int,
            Err(e) => e.to_int(),
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut IO as *mut _
    }
}

/// Marker type for an IO implementation that doesn't implement `std::io::Read`
/// and `std::io::Write`.
pub enum AnyIo {}
#[cfg(feature = "std")]
/// Marker type for an IO implementation that implements both `std::io::Read`
/// and `std::io::Write`.
pub enum Stream {}

/// Read and write bytes or packets.
///
/// Implementors represent a duplex socket or file descriptor that can be read
/// from or written to.
///
/// You can wrap any type of `Io` with `Context::establish` to protect that
/// communication channel with (D)TLS. That `Context` then also implements `Io`
/// so you can use it interchangeably.
///
/// If you are using byte streams and are using `std`, you don't need this trait
/// and can rely on `std::io::Read` and `std::io::Write` instead.
pub trait Io {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn send(&mut self, buf: &[u8]) -> Result<usize>;
}

impl<IO: Io> IoCallback<AnyIo> for IO {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Io::recv(self, buf)
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        Io::send(self, buf)
    }
}

#[cfg(feature = "std")]
impl<IO: Read + Write> IoCallback<Stream> for IO {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.read(buf).map_err(|e| match e {
            ref e if e.kind() == std::io::ErrorKind::WouldBlock => Error::SslWantRead,
            _ => Error::NetRecvFailed
        })
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        self.write(buf).map_err(|e| match e {
            ref e if e.kind() == std::io::ErrorKind::WouldBlock => Error::SslWantWrite,
            _ => Error::NetSendFailed
        })
    }
}

#[cfg(feature = "std")]
/// A `UdpSocket` on which `connect` was successfully called.
///
/// Construct this type using `ConnectedUdpSocket::connect`.
pub struct ConnectedUdpSocket {
    socket: UdpSocket,
}

#[cfg(feature = "std")]
impl ConnectedUdpSocket {
    pub fn connect<A: std::net::ToSocketAddrs>(socket: UdpSocket, addr: A) -> StdResult<Self, (IoError, UdpSocket)> {
        match socket.connect(addr) {
            Ok(_) => Ok(ConnectedUdpSocket {
                socket,
            }),
            Err(e) => Err((e, socket)),
        }
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

#[cfg(feature = "std")]
impl Io for ConnectedUdpSocket {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.socket.recv(buf) {
            Ok(i) => Ok(i),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::SslWantRead),
            Err(_) => Err(Error::NetRecvFailed)
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        self.socket.send(buf).map_err(|_| Error::NetSendFailed)
    }
}

impl<T: IoCallbackUnsafe<AnyIo>> Io for Context<T> {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Context::recv(self, buf)
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        Context::send(self, buf)
    }
}

#[cfg(feature = "std")]
/// Implements [`std::io::Read`] whenever T implements `Read`, too. This ensures that
/// `Read`, which is designated for byte-oriented sources, is only implemented when the
/// underlying [`IoCallbackUnsafe`] is byte-oriented, too. Specifically, this means that it is implemented
/// for `Context<TcpStream>`, i.e. TLS connections but not for DTLS connections.
impl<T: IoCallbackUnsafe<Stream>> Read for Context<T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.recv(buf) {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Err(IoErrorKind::WouldBlock.into()),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i),
        }
    }
}

#[cfg(feature = "std")]
/// Implements [`std::io::Write`] whenever T implements `Write`, too. This ensures that
/// `Write`, which is designated for byte-oriented sinks, is only implemented when the
/// underlying [`IoCallbackUnsafe`] is byte-oriented, too. Specifically, this means that it is implemented
/// for `Context<TcpStream>`, i.e. TLS connections but not for DTLS connections.
impl<T: IoCallbackUnsafe<Stream>> Write for Context<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match self.send(buf) {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Err(IoErrorKind::WouldBlock.into()),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}
