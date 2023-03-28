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
use std::{
    future::Future,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
/// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.
pub enum AsyncStream {}

// TODO: Add enum `AnyAsyncIo` as marker type for an IO implementation that
// doesn't implement `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.

// TODO: Add `AsyncIo` trait for async IO that that doesn't implement
// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`. For example:
//     pub trait AsyncIo {
//        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
//         async fn send(&mut self, buf: &[u8]) -> Result<usize>;
//     }
// Could implement by using `async-trait` crate or
// #![feature(async_fn_in_trait)] or Associated Types

impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream>
    for (&'a mut TaskContext<'b>, &'c mut IO)
{
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

impl<T: Unpin + AsyncRead + AsyncWrite + 'static> Context<T> {
    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.prepare_handshake(io, hostname)?;

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

// TODO: AsyncIo impl for tokio::net::UdpSocket
