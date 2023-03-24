/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(all(feature = "std", feature = "async"))]
#![allow(unused)]

use mbedtls_sys::ssl_close_notify;

use crate::{
    error::{Error, IntoResult, Result},
    ssl::{
        context::Context,
        io::{IoCallback, IoCallbackUnsafe},
        Config,
    },
};
use async_trait::async_trait;
use std::{
    future::Future,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    inner: S,
    write_tracker: WriteTracker,
}

impl<S> AsyncIoAdapter<S> {
    pub fn new(io: S) -> Self {
        Self {
            inner: io,
            write_tracker: WriteTracker::new(),
        }
    }

    pub fn handle(&self) -> &S {
        &self.inner
    }
}

pub type AsyncContext<T> = Context<AsyncIoAdapter<T>>;

/// Marker type for an IO implementation that doesn't implement `tokio::io::
/// AsyncRead` and `tokio::io:: AsyncWrite`.
pub enum AnyAsyncIo {}
#[cfg(feature = "std")]
/// Marker type for an IO implementation that implements both `tokio::io::
/// AsyncRead` and `tokio::io:: AsyncWrite`.
pub enum AsyncStream {}

#[async_trait]
pub trait AsyncIo {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn send(&mut self, buf: &[u8]) -> Result<usize>;
}

impl<'a, 'b, 'c, IO: AsyncIo> IoCallback<AnyAsyncIo> for (&'a mut TaskContext<'b>, &'c mut IO) {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.1.recv(buf).as_mut().poll(self.0) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
            Poll::Pending => Err(Error::SslWantRead),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        match self.1.send(buf).as_mut().poll(self.0) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
            Poll::Pending => Err(Error::SslWantWrite),
        }
    }
}

impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream> for (&'a mut TaskContext<'b>, &'c mut IO) {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buf = ReadBuf::new(buf);
        let io = Pin::new(&mut self.1);
        match io.poll_read(self.0, &mut buf) {
            Poll::Ready(Ok(_)) => Ok(buf.filled().len()),
            Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
            Poll::Pending => Err(Error::SslWantRead),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let io = Pin::new(&mut self.1);
        match io.poll_write(self.0, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
            Poll::Pending => Err(Error::SslWantWrite),
        }
    }
}

struct HandshakeFuture<'a, T>(&'a mut AsyncIoAdapter<Context<T>>);

impl<T> Future for HandshakeFuture<'_, T> where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut TaskContext) -> std::task::Poll<Self::Output> {
        self.0.inner.with_bio_async(ctx, |sslctx| {
            match sslctx.handshake() {
                Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Poll::Pending,
                Err(e) => Poll::Ready(Err(e)),
                Ok(()) => Poll::Ready(Ok(())),
            }
        }).unwrap_or(Poll::Ready(Err(Error::NetSendFailed)))
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite + 'static> AsyncIoAdapter<Context<T>> {
    pub async fn accept_async<IoType>(
        config: Arc<Config>,
        io: T,
        hostname: Option<&str>,
    ) -> IoResult<AsyncIoAdapter<Context<T>>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        let mut async_io = AsyncIoAdapter::new(Context::new(config));
        async_io
            .establish_async(io, hostname)
            .await
            .map_err(|e| crate::private::error_to_io_error(e))?;
        Ok(async_io)
    }

    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.inner.prepare_handshake(io, hostname)?;

        HandshakeFuture(self).await
    }
}

impl<T: AsyncRead> AsyncRead for AsyncIoAdapter<Context<T>>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        if self.inner.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        self.inner.with_bio_async(cx, |sslctx| {
            match sslctx.recv(buf.initialize_unfilled()) {
                Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(())),
                Err(Error::SslWantRead) => Poll::Pending,
                Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
                Ok(i) => {
                    buf.advance(i);
                    Poll::Ready(Ok(()))
                }
            }
        }).unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::NetRecvFailed))))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AsyncIoAdapter<Context<T>>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.inner.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        let AsyncIoAdapter { inner, write_tracker } = &mut*self;

        let result = inner.with_bio_async(cx, |sslctx| {
            write_tracker.adjust_buf(buf);
            match sslctx.send(buf) {
                Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
                Err(Error::SslWantWrite) => Poll::Pending,
                Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
                Ok(i) => Poll::Ready(Ok(i)),
            }
        }).unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::NetSendFailed))));

        write_tracker.post_write(buf, &result);

        cx.waker().clone().wake();

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        // We can only flush the actual IO here.
        // To flush mbedtls we need writes with the same buffer until complete.
        let io = &mut self
            .inner
            .io_mut()
            .ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?;
        let stream = Pin::new(io);
        stream.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        if self.inner.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        match self.inner.with_bio_async(cx, Context::close_notify).unwrap_or(Err(Error::NetSendFailed)) {
            Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Poll::Pending,
            Err(e) => {
                self.inner.drop_io();
                Poll::Ready(Err(crate::private::error_to_io_error(e)))
            }
            Ok(()) => {
                self.inner.drop_io();
                Poll::Ready(Ok(()))
            }
        }
    }
}

// TODO: AsyncIo impl for Context<AsyncIoAdapter<T>>
