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

/// mbedtls_ssl_write() has some weird semantics w.r.t non-blocking I/O:
///
/// > When this function returns MBEDTLS_ERR_SSL_WANT_WRITE/READ, it must be
/// > called later **with the same arguments**, until it returns a value greater
/// > than or equal to 0. When the function returns MBEDTLS_ERR_SSL_WANT_WRITE
/// > there may be some partial data in the output buffer, however this is not
/// > yet sent.
///
/// WriteTracker is used to ensure we pass the same data in that scenario.
///
/// Reference:
/// https://github.com/Mbed-TLS/mbedtls/blob/981743de6fcdbe672e482b6fd724d31d0a0d2476/include/mbedtls/ssl.h#L4137-L4141
pub(super) struct WriteTracker {
    pending: Option<Box<DigestAndLen>>,
}

/// A struct that use to store digest data & its length in the current write
/// buff
///
/// This struct has two fields: `digest`, which is an array of 20 bytes
/// representing the SHA-1 digest of the data, and `len`, which is the length of
/// the data in bytes.
///
/// The `digest` field is only available when the program is compiled with debug
/// assertions enabled.
struct DigestAndLen {
    #[cfg(debug_assertions)]
    digest: [u8; 20], // SHA-1
    len: usize,
}

impl WriteTracker {
    pub(super) fn new() -> Self {
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

    fn adjust_buf<'a>(&self, buf: &'a [u8]) -> IoResult<&'a [u8]> {
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

    fn post_write(&mut self, buf: &[u8], res: &Poll<IoResult<usize>>) {
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

/// Marker type for an IO implementation that implements both
/// [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
pub enum AsyncStream {}

/// Marker type for an IO implementation that
/// doesn't implement [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
pub enum AnyAsyncIo {}

/// Async read or write bytes or packets.
///
/// Implementors represent a socket or file descriptor that can be read from or
/// written to.
///
/// By implementing [`AsyncSend`] and [`AsyncRecv`] you can wrap any type of
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
impl<T: AsyncSend + AsyncRecv + Unpin + ?Sized + Send> AsyncIo for T {
    async fn recv(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_fn(move |cx| {
            let mut buf = ReadBuf::new(buf);
            match Pin::new(&mut *self).poll_recv(cx, &mut buf) {
                Poll::Ready(t) => t,
                Poll::Pending => return Poll::Pending,
            }?;
            Poll::Ready(Ok(buf.filled().len()))
        })
        .await
    }

    async fn send(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_fn(|cx| Pin::new(&mut *self).poll_send(cx, buf)).await
    }
}

/// Send bytes to a source.
///
/// This trait is simpler analogous to the [`tokio::io::AsyncWrite`] trait but
/// much simpler. Since this is for any IO which may not has state of connection
/// or has concept of stream so it does not require the func
/// [`tokio::io::AsyncWrite::poll_flush`] and
/// [`tokio::io::AsyncWrite::poll_shutdown`] in [`tokio::io::AsyncWrite`].
pub trait AsyncSend {
    fn poll_send(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<StdResult<usize, IoError>>;
}

impl<T: ?Sized + AsyncSend + Unpin> AsyncSend for &mut T {
    fn poll_send(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<StdResult<usize, IoError>> {
        Pin::new(&mut **self).poll_send(cx, buf)
    }
}

/// Receive bytes from a source.
///
/// This trait is analogous to the [`tokio::io::AsyncRead`] trait but much
/// simpler.
pub trait AsyncRecv {
    fn poll_recv(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>>;
}

impl<T: ?Sized + AsyncRecv + Unpin> AsyncRecv for &mut T {
    fn poll_recv(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut **self).poll_recv(cx, buf)
    }
}

macro_rules! async_callback_func_impl {
    ($recv_func:ident, $send_func:ident) => {
        fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            let mut buf = ReadBuf::new(buf);
            let io = Pin::new(&mut self.1);
            match io.$recv_func(self.0, &mut buf) {
                Poll::Ready(Ok(_)) => Ok(buf.filled().len()),
                Poll::Ready(Err(_)) => Err(Error::NetRecvFailed),
                Poll::Pending => Err(Error::SslWantRead),
            }
        }

        fn send(&mut self, buf: &[u8]) -> Result<usize> {
            let io = Pin::new(&mut self.1);
            match io.$send_func(self.0, buf) {
                Poll::Ready(Ok(n)) => Ok(n),
                Poll::Ready(Err(_)) => Err(Error::NetSendFailed),
                Poll::Pending => Err(Error::SslWantWrite),
            }
        }
    };
}

impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + Unpin> IoCallback<AsyncStream> for (&'a mut TaskContext<'b>, &'c mut IO) {
    async_callback_func_impl! {poll_read,poll_write}
}

impl<'a, 'b, 'c, IO: AsyncRecv + AsyncSend + Unpin> IoCallback<AnyAsyncIo> for (&'a mut TaskContext<'b>, &'c mut IO) {
    async_callback_func_impl! {poll_recv,poll_send}
}

struct HandshakeFuture<'a, T, IoType>(&'a mut Context<T>, &'a PhantomData<IoType>);

impl<T, IoType> Future for HandshakeFuture<'_, T, IoType>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
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

impl<T: Unpin> Context<T> {
    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.prepare_handshake(io, hostname)?;

        self.handshake_async::<IoType>().await
    }

    pub async fn handshake_async<IoType>(&mut self) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        HandshakeFuture(self, &PhantomData::<IoType>).await
    }
}

macro_rules! async_recv_func_impl {
    ($func_name:ident) => {
        fn $func_name(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
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
    };
}

macro_rules! async_send_func_impl {
    ($func_name:ident) => {
        fn $func_name(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
            if self.handle().session.is_null() {
                return Poll::Ready(Err(IoError::new(IoErrorKind::Other, "stream has been shutdown")));
            }

            let result = self
                .with_bio_async(cx, |ssl_ctx| {
                    ssl_ctx.write_tracker.adjust_buf(buf)?;
                    match ssl_ctx.send(buf) {
                        Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
                        Err(Error::SslWantWrite) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
                        Ok(i) => Poll::Ready(Ok(i)),
                    }
                })
                .unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::NetSendFailed))));

            self.write_tracker.post_write(buf, &result);

            cx.waker().clone().wake();

            result
        }
    };
}

impl<T: AsyncRead> AsyncRead for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    async_recv_func_impl! {poll_read}
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    async_send_func_impl! {poll_write}

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        // We can only flush the actual IO here.
        // To flush mbedtls we need writes with the same buffer until complete.
        let io = &mut self
            .io_mut()
            .ok_or(IoError::new(IoErrorKind::Other, "stream has been shutdown"))?;
        let stream = Pin::new(io);
        stream.poll_flush(cx)
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

impl<T: AsyncRecv> AsyncRecv for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AnyAsyncIo>,
{
    async_recv_func_impl! {poll_recv}
}

impl<T: AsyncSend> AsyncSend for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AnyAsyncIo>,
{
    async_send_func_impl! {poll_send}
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
            Ok(_) => Ok(ConnectedAsyncUdpSocket { socket }),
            Err(e) => Err((e, socket)),
        }
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl AsyncRecv for ConnectedAsyncUdpSocket {
    fn poll_recv(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        self.socket.poll_recv(cx, buf)
    }
}

impl AsyncSend for ConnectedAsyncUdpSocket {
    fn poll_send(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<StdResult<usize, IoError>> {
        self.socket.poll_send(cx, buf)
    }
}
