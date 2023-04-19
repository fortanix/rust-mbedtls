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
use core::marker::PhantomData;
use std::{
    future::Future,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    pin::Pin,
    result::Result as StdResult,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    macros::support::poll_fn,
    net::UdpSocket,
};

/// Marker type for an IO implementation that implements both
/// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.
pub enum AsyncStream {}

/// Marker type for an IO implementation that
/// doesn't implement [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
pub enum AnyAsyncIo {}

/// Async read or write bytes or packets.
///
/// Implementors represent a socket or file descriptor that can be read from or
/// written to.
///
/// By implementing [`AsyncIo`] you can wrap any type of
/// [`AsyncIo`] with [`Context<T>::establish_async`] to protect that
/// communication channel with (D)TLS. That [`Context`] then also implements
/// [`AsyncIo`] so you can use it interchangeably.
///
/// If you are using byte streams and are using [`tokio::io`], you don't need
/// this trait and can rely on [`tokio::io::AsyncRead`] and
/// [`tokio::io::AsyncWrite`] instead.
#[async_trait]
pub trait AsyncIo {
    async fn recv(&mut self, buf: &mut [u8]) -> IoResult<usize>;
    async fn send(&mut self, buf: &[u8]) -> IoResult<usize>;
}

#[async_trait]
impl<T: AsyncIo + Send> AsyncIo for Context<T> {
    async fn recv(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.io_mut()
            .ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
            .recv(buf)
            .await
    }

    async fn send(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.io_mut()
            .ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?
            .send(buf)
            .await
    }
}

impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream>
    for (&'a mut TaskContext<'b>, &'c mut IO)
{
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buf = ReadBuf::new(buf);
        let io = Pin::new(&mut self.1);
        match io.poll_read(self.0, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
            Poll::Pending => Err(Error::SslWantRead),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let io = Pin::new(&mut self.1);
        match io.poll_write(self.0, buf) {
            Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Pending => Err(Error::SslWantWrite),
        }
    }
}

impl<'a, 'b, 'c, IO: AsyncIo> IoCallback<AnyAsyncIo> for (&'a mut TaskContext<'b>, &'c mut IO) {
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match Pin::new(&mut self.1.recv(buf)).poll(self.0) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
            Poll::Pending => Err(Error::SslWantRead),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        match Pin::new(&mut self.1.send(buf)).poll(self.0) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
            Poll::Pending => Err(Error::SslWantWrite),
        }
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite + 'static> Context<T> {
    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        struct HandshakeFuture<'a, T>(&'a mut Context<T>);
        impl<T> Future for HandshakeFuture<'_, T>
        where
            for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
        {
            type Output = Result<()>;
            fn poll(mut self: Pin<&mut Self>, ctx: &mut TaskContext) -> std::task::Poll<Self::Output> {
                self.0
                    .with_bio_async(ctx, |ssl_ctx| match ssl_ctx.handshake() {
                        Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(e)),
                        Ok(()) => Poll::Ready(Ok(())),
                    })
                    .unwrap_or(Poll::Ready(Err(Error::NetSendFailed)))
            }
        }

        self.prepare_handshake(io, hostname)?;

        HandshakeFuture(self).await
    }
}

impl<T: AsyncRead> AsyncRead for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.recv(buf.initialize_unfilled()) {
            Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(())),
            Err(Error::SslWantRead) => Poll::Pending,
            Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
            Ok(i) => {
                buf.advance(i);
                Poll::Ready(Ok(()))
            }
        })
        .unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::NetRecvFailed))))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        self
            .with_bio_async(cx, |ssl_ctx| match ssl_ctx.async_write(buf) {
                Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
                Err(Error::SslWantWrite) => Poll::Pending,
                Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
                Ok(i) => Poll::Ready(Ok(i)),
            })
            .unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::NetSendFailed))))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        match self
            .with_bio_async(cx, Context::flush_output)
            .unwrap_or(Err(Error::NetSendFailed))
        {
            Err(Error::SslWantWrite) => Poll::Pending,
            Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        if self.handle().session.is_null() {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
        }

        match self
            .with_bio_async(cx, Context::close_notify)
            .unwrap_or(Err(Error::NetSendFailed))
        {
            Err(Error::SslWantRead) | Err(Error::SslWantWrite) => Poll::Pending,
            Err(e) => {
                self.drop_io();
                Poll::Ready(Err(crate::private::error_to_io_error(e)))
            }
            Ok(()) => {
                self.drop_io();
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// A wrapper of [`tokio::net::UdpSocket`] on which
/// [`tokio::net::UdpSocket::connect`] was successfully called.
///
/// Construct this type using [`ConnectedAsyncUdpSocket::connect`].
pub struct ConnectedAsyncUdpSocket {
    socket: UdpSocket,
}

impl ConnectedAsyncUdpSocket {
    pub async fn connect<A: tokio::net::ToSocketAddrs>(socket: UdpSocket, addr: A) -> StdResult<Self, (IoError, UdpSocket)> {
        match socket.connect(addr).await {
            Ok(()) => Ok(ConnectedAsyncUdpSocket { socket }),
            Err(e) => Err((e, socket)),
        }
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

#[async_trait]
impl AsyncIo for ConnectedAsyncUdpSocket {
    async fn recv(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_fn(|cx| {
            let mut buf = ReadBuf::new(buf);
            match self.socket.poll_recv(cx, &mut buf) {
                Poll::Ready(res) => res,
                Poll::Pending => return Poll::Pending,
            }?;
            Poll::Ready(Ok(buf.filled().len()))
        })
        .await
    }

    async fn send(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_fn(|cx| self.socket.poll_send(cx, buf)).await
    }
}
