/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(all(feature = "std", feature = "async"))]

use crate::{
    error::{Error, Result},
    ssl::{
        context::Context,
        io::{IoCallback, IoCallbackUnsafe},
    },
};
use async_trait::async_trait;
use std::{
    cell::Cell,
    future::Future,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    pin::Pin,
    ptr::null_mut,
    rc::Rc,
    result::Result as StdResult,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
};

#[derive(Clone)]
pub struct ErasedContext(Rc<Cell<*mut ()>>);

unsafe impl Send for ErasedContext {}

impl ErasedContext {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(null_mut())))
    }

    pub unsafe fn get(&self) -> Option<&mut TaskContext<'_>> {
        let ptr = self.0.get();
        if ptr.is_null() {
            None
        } else {
            Some(&mut *(ptr as *mut _))
        }
    }

    pub fn set(&self, cx: &mut TaskContext<'_>) {
        self.0.set(cx as *mut _ as *mut ());
    }

    pub fn clear(&self) {
        self.0.set(null_mut());
    }
}

// mbedtls_ssl_write() has some weird semantics w.r.t non-blocking I/O:
//
// > When this function returns MBEDTLS_ERR_SSL_WANT_WRITE/READ, it must be
// > called later **with the same arguments**, until it returns a value greater
// > than or equal to 0. When the function returns MBEDTLS_ERR_SSL_WANT_WRITE
// > there may be some partial data in the output buffer, however this is not
// > yet sent.
//
// WriteTracker is used to ensure we pass the same data in that scenario.
//
// Reference:
// https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
pub struct WriteTracker {
    pending: Option<Box<DigestAndLen>>,
}

struct DigestAndLen {
    #[cfg(debug_assertions)]
    digest: [u8; 20], // SHA-1
    len: usize,
}

impl WriteTracker {
    fn new() -> Self {
        WriteTracker { pending: None }
    }

    #[cfg(debug_assertions)]
    fn digest(buf: &[u8]) -> [u8; 20] {
        use crate::hash::{Md, Type};
        let mut out = [0u8; 20];
        let res = Md::hash(Type::Sha1, buf, &mut out[..]);
        assert_eq!(res, Ok(out.len()));
        out
    }

    pub fn adjust_buf<'a>(&self, buf: &'a [u8]) -> IoResult<&'a [u8]> {
        match self.pending.as_ref() {
            None => Ok(buf),
            Some(pending) => {
                if pending.len <= buf.len() {
                    let buf = &buf[..pending.len];

                    // We only do this check in debug mode since it's an expensive check.
                    #[cfg(debug_assertions)]
                    if Self::digest(buf) == pending.digest {
                        return Ok(buf);
                    }

                    #[cfg(not(debug_assertions))]
                    return Ok(buf);
                }
                Err(IoError::new(
                    IoErrorKind::Other,
                    "mbedtls expects the same data if the previous call to poll_write() returned Poll::Pending",
                ))
            }
        }
    }

    pub fn post_write(&mut self, buf: &[u8], res: &Poll<IoResult<usize>>) {
        match res {
            &Poll::Pending => {
                if self.pending.is_none() {
                    self.pending = Some(Box::new(DigestAndLen {
                        #[cfg(debug_assertions)]
                        digest: Self::digest(buf),
                        len: buf.len(),
                    }));
                }
            }
            _ => {
                self.pending = None;
            }
        }
    }
}

pub struct AsyncIoAdapter<S> {
    pub inner: S,
    pub ecx: ErasedContext,
    pub write_tracker: WriteTracker,
}

impl<S> AsyncIoAdapter<S> {
    pub fn new(io: S) -> Self {
        Self {
            inner: io,
            ecx: ErasedContext::new(),
            write_tracker: WriteTracker::new(),
        }
    }
}

pub type AsyncContext<T> = Context<AsyncIoAdapter<T>>;

/// Marker type for an IO implementation that doesn't implement `tokio::io:: AsyncRead`
/// and `tokio::io:: AsyncWrite`.
pub enum AnyAsyncIo {}
#[cfg(feature = "std")]
/// Marker type for an IO implementation that implements both `tokio::io:: AsyncRead`
/// and `tokio::io:: AsyncWrite`.
pub enum AsyncStream {}

#[async_trait]
pub trait AsyncIo {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn send(&mut self, buf: &[u8]) -> Result<usize>;
}

impl<IO: AsyncIo> IoCallback<AnyAsyncIo> for AsyncIoAdapter<IO> {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(cx) = unsafe { self.ecx.get() } {
            let mut pinned_future = Box::pin(AsyncIo::recv(&mut self.inner, buf));
            match pinned_future.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => Ok(n),
                Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
                Poll::Pending => Err(Error::SslWantRead),
            }
        } else {
            Err(Error::NetRecvFailed)
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        if let Some(cx) = unsafe { self.ecx.get() } {
            let mut pinned_future = Box::pin(AsyncIo::send(&mut self.inner, buf));
            match pinned_future.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => Ok(n),
                Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
                Poll::Pending => Err(Error::SslWantWrite),
            }
        } else {
            Err(Error::NetSendFailed)
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream> for AsyncIoAdapter<IO> {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(cx) = unsafe { self.ecx.get() } {
            let mut buf = ReadBuf::new(buf);
            let io = Pin::new(&mut self.inner);
            match io.poll_read(cx, &mut buf) {
                Poll::Ready(Ok(_)) => Ok(buf.filled().len()),
                Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
                Poll::Pending => Err(Error::SslWantRead),
            }
        } else {
            Err(Error::NetRecvFailed)
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        if let Some(cx) = unsafe { self.ecx.get() } {
            let io = Pin::new(&mut self.inner);
            match io.poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => Ok(n),
                Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
                Poll::Pending => Err(Error::SslWantWrite),
            }
        } else {
            Err(Error::NetSendFailed)
        }
    }
}

/// A `tokio::net::UdpSocket` on which `connect` was successfully called.
///
/// Construct this type using `ConnectedAsyncUdpSocket::connect`.
pub struct ConnectedAsyncUdpSocket {
    socket: UdpSocket,
}

impl ConnectedAsyncUdpSocket {
    pub async fn connect<A: tokio::net::ToSocketAddrs>(socket: UdpSocket, addr: A) -> StdResult<Self, (IoError, UdpSocket)> {
        match socket.connect(addr).await {
            Ok(_) => Ok(ConnectedAsyncUdpSocket { socket }),
            Err(e) => Err((e, socket)),
        }
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

#[async_trait]
impl AsyncIo for ConnectedAsyncUdpSocket {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let socket = &mut self.socket;
        match socket.recv(buf).await {
            Ok(i) => Ok(i),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::SslWantRead),
            Err(_) => Err(Error::NetRecvFailed),
        }
    }

    async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let socket = &mut self.socket;
        socket.send(buf).await.map_err(|_| Error::NetSendFailed)
    }
}

// todo: this impl should be wrong, might need to create a impl of Future on Context::recv & Context::send to handle return from inner callback
#[async_trait]
impl<T: IoCallbackUnsafe<AnyAsyncIo> + Send> AsyncIo for Context<AsyncIoAdapter<T>> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Context::recv(self, buf)
    }

    async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        Context::send(self, buf)
    }
}
